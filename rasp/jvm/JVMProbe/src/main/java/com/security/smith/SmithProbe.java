package com.security.smith;

import com.security.smith.asm.SmithClassVisitor;
import com.security.smith.asm.SmithClassWriter;
import com.security.smith.client.Operate;
import com.security.smith.client.ProbeClient;
import com.security.smith.client.ProbeNotify;
import com.security.smith.log.SmithLogger;
import com.security.smith.type.*;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.objectweb.asm.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class SmithProbe implements ClassFileTransformer, ProbeNotify {
    private static final SmithProbe ourInstance = new SmithProbe();
    private static final int DEFAULT_QUEUE_SIZE = 1000;

    public static SmithProbe getInstance() {
        return ourInstance;
    }

    public SmithProbe() {
        disable = false;
        clientConnected = false;

        smithClasses = new HashMap<>();
        smithFilters = new ConcurrentHashMap<>();
        smithBlocks = new ConcurrentHashMap<>();
        probeClient = new ProbeClient(this);
        traceQueue = new ArrayBlockingQueue<>(DEFAULT_QUEUE_SIZE);
    }

    public void setInst(Instrumentation inst) {
        this.inst = inst;
    }

    public void init() {
        Yaml yaml = new Yaml(new Constructor(SmithClass.class));
        InputStream inputStream = this.getClass().getResourceAsStream("/class.yaml");

        for (Object object : yaml.loadAll(inputStream)) {
            SmithClass smithClass = (SmithClass) object;
            smithClasses.put(smithClass.getName(), smithClass);
        }
    }

    public void start() {
        SmithLogger.logger.info("probe start");

        inst.addTransformer(this, true);
        reloadClasses();

        Thread clientThread = new Thread(probeClient::start);

        clientThread.setDaemon(true);
        clientThread.start();

        Thread traceThread = new Thread(this::probeTraceThread);

        traceThread.setDaemon(true);
        traceThread.start();
    }

    private void reloadClasses() {
        reloadClasses(smithClasses.keySet());
    }

    private void reloadClasses(Collection<String> classes) {
        List<Class<?>> cls = new ArrayList<>();

        for (String className : classes) {
            try {
                Class<?> cl = Class.forName(className, true, ClassLoader.getSystemClassLoader());
                cls.add(cl);
            } catch (ClassNotFoundException e) {
                SmithLogger.logger.info("class not found: " + className);
            }
        }

        SmithLogger.logger.info("reload: " + cls);

        try {
            inst.retransformClasses(cls.toArray(new Class<?>[0]));
        } catch (UnmodifiableClassException e) {
            SmithLogger.exception(e);
        }
    }

    public void trace(int classID, int methodID, Object[] args, Object ret, boolean canBlock) {
        if (!clientConnected)
            return;

        SmithTrace smithTrace = new SmithTrace();

        smithTrace.setClassID(classID);
        smithTrace.setMethodID(methodID);
        smithTrace.setRet(ret);
        smithTrace.setArgs(args);
        smithTrace.setStackTrace(Thread.currentThread().getStackTrace());

        traceQueue.offer(smithTrace);

        if (!canBlock)
            return;

        SmithBlock block = smithBlocks.get(new ImmutablePair<>(smithTrace.getClassID(), smithTrace.getMethodID()));

        if (block == null)
            return;

        if (Arrays.stream(block.getRules()).anyMatch(rule -> {
            if (rule.getIndex() >= args.length)
                return false;

            return Pattern.compile(rule.getRegex()).matcher(args[rule.getIndex()].toString()).find();
        })) {
            throw new SecurityException("API blocked by RASP");
        }
    }

    private void probeTraceThread() {
        SmithLogger.logger.info("probe trace thread start");

        while (true) {
            try {
                SmithTrace smithTrace = traceQueue.take();
                SmithFilter filter = smithFilters.get(new ImmutablePair<>(smithTrace.getClassID(), smithTrace.getMethodID()));

                if (filter == null) {
                    probeClient.write(Operate.traceOperate, smithTrace);
                    continue;
                }

                Predicate<SmithMatchRule> pred = rule -> {
                    Object[] args = smithTrace.getArgs();

                    if (rule.getIndex() >= args.length)
                        return false;

                    return Pattern.compile(rule.getRegex()).matcher(args[rule.getIndex()].toString()).find();
                };

                SmithMatchRule[] include = filter.getInclude();
                SmithMatchRule[] exclude = filter.getExclude();

                if (include.length > 0 && Arrays.stream(include).noneMatch(pred))
                    continue;

                if (exclude.length > 0 && Arrays.stream(exclude).anyMatch(pred))
                    continue;

                probeClient.write(Operate.traceOperate, smithTrace);

            } catch (InterruptedException e) {
                SmithLogger.exception(e);
            }
        }
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (disable)
            return null;

        Type classType = Type.getType(classBeingRedefined);
        SmithClass smithClass = smithClasses.get(classType.getClassName());

        if (smithClass == null)
            return null;

        SmithLogger.logger.info("transform: " + className);

        try {
            ClassReader classReader = new ClassReader(classfileBuffer);
            ClassWriter classWriter = new SmithClassWriter(ClassWriter.COMPUTE_MAXS);

            ClassVisitor classVisitor = new SmithClassVisitor(
                    Opcodes.ASM8,
                    classWriter,
                    smithClass.getId(),
                    classType,
                    smithClass.getMethods().stream().collect(Collectors.toMap(method -> method.getName() + method.getDesc(), method -> method))
            );

            classReader.accept(classVisitor, ClassReader.EXPAND_FRAMES);

            return classWriter.toByteArray();
        } catch (Exception e) {
            SmithLogger.exception(e);
        }

        return null;
    }

    @Override
    public void onConnect() {
        SmithLogger.logger.info("on connect");
        clientConnected = true;
    }

    @Override
    public void onDisconnect() {
        SmithLogger.logger.info("on disconnect");
        clientConnected = false;
    }

    @Override
    public void onConfig(String config) {
        SmithLogger.logger.info("on config: " + config);

        Set<String> classes = new HashSet<>(smithClasses.keySet());

        smithClasses.clear();

        Yaml yaml = new Yaml(new Constructor(SmithClass.class));

        for (Object object : yaml.loadAll(config)) {
            SmithClass smithClass = (SmithClass) object;
            smithClasses.put(smithClass.getName(), smithClass);
        }

        classes.addAll(smithClasses.keySet());
        reloadClasses(classes);
    }

    @Override
    public void onControl(int action) {
        SmithLogger.logger.info("on control: " + action);
        disable = action == emControlAction.stopAction.ordinal();
        reloadClasses();
    }

    @Override
    public void onDetect() {
        SmithLogger.logger.info("on detect");

        Set<SmithJar> smithJars = new HashSet<>();

        for (Class<?> cl : inst.getAllLoadedClasses()) {
            CodeSource codeSource = cl.getProtectionDomain().getCodeSource();

            if (codeSource == null)
                continue;

            SmithJar smithJar = new SmithJar();
            smithJar.setPath(codeSource.getLocation().toString());

            if (smithJars.contains(smithJar))
                continue;

            Package pkg = cl.getPackage();

            smithJar.setSpecificationTitle(pkg.getSpecificationTitle());
            smithJar.setSpecificationVersion(pkg.getSpecificationVersion());
            smithJar.setImplementationTitle(pkg.getImplementationTitle());
            smithJar.setImplementationVersion(pkg.getImplementationVersion());

            smithJars.add(smithJar);
        }

        probeClient.write(Operate.detectOperate, Collections.singletonMap("jars", smithJars));
    }

    @Override
    public void onFilter(SmithFilter[] filters) {
        smithFilters.clear();

        for (SmithFilter filter : filters) {
            smithFilters.put(
                    new ImmutablePair<>(filter.getClassID(), filter.getMethodID()),
                    filter
            );
        }
    }

    @Override
    public void onBlock(SmithBlock[] blocks) {
        smithBlocks.clear();

        for (SmithBlock block : blocks) {
            smithBlocks.put(
                    new ImmutablePair<>(block.getClassID(), block.getMethodID()),
                    block
            );
        }
    }

    enum emControlAction {
        stopAction,
        startAction,
    }

    private Boolean disable;
    private Boolean clientConnected;
    private Instrumentation inst;
    private final ProbeClient probeClient;
    private final ArrayBlockingQueue<SmithTrace> traceQueue;
    private final Map<String, SmithClass> smithClasses;
    private final Map<Pair<Integer, Integer>, SmithFilter> smithFilters;
    private final Map<Pair<Integer, Integer>, SmithBlock> smithBlocks;
}
