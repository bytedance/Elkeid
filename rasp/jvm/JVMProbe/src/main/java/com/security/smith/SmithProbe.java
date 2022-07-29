package com.security.smith;

import com.lmax.disruptor.EventHandler;
import com.lmax.disruptor.InsufficientCapacityException;
import com.lmax.disruptor.RingBuffer;
import com.lmax.disruptor.dsl.Disruptor;
import com.lmax.disruptor.util.DaemonThreadFactory;
import com.security.smith.asm.SmithClassVisitor;
import com.security.smith.asm.SmithClassWriter;
import com.security.smith.client.Operate;
import com.security.smith.client.ProbeClient;
import com.security.smith.client.ProbeNotify;
import com.security.smith.log.SmithLogger;
import com.security.smith.module.Patch;
import com.security.smith.type.*;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.objectweb.asm.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SmithProbe implements ClassFileTransformer, ProbeNotify, EventHandler<SmithTrace> {
    private static final SmithProbe ourInstance = new SmithProbe();
    private static final int TRACE_BUFFER_SIZE = 1024;
    private static final int CLASS_MAX_ID = 30;
    private static final int METHOD_MAX_ID = 20;
    private static final int DEFAULT_QUOTA = 12000;

    private Boolean disable;
    private Boolean clientConnected;
    private Instrumentation inst;
    private final ProbeClient probeClient;
    private final Disruptor<SmithTrace> disruptor;
    private final Map<String, SmithClass> smithClasses;
    private final Map<String, Patch> smithPatches;
    private final Map<Pair<Integer, Integer>, SmithFilter> smithFilters;
    private final Map<Pair<Integer, Integer>, SmithBlock> smithBlocks;
    private final Map<Pair<Integer, Integer>, Integer> smithLimits;
    private final AtomicIntegerArray[] smithQuotas;

    enum Action {
        STOP,
        START
    }

    public static SmithProbe getInstance() {
        return ourInstance;
    }

    public SmithProbe() {
        disable = false;
        clientConnected = false;

        smithClasses = new ConcurrentHashMap<>();
        smithPatches = new ConcurrentHashMap<>();
        smithFilters = new ConcurrentHashMap<>();
        smithBlocks = new ConcurrentHashMap<>();
        smithLimits = new ConcurrentHashMap<>();

        probeClient = new ProbeClient(this);
        disruptor = new Disruptor<>(SmithTrace::new, TRACE_BUFFER_SIZE, DaemonThreadFactory.INSTANCE);
        smithQuotas = Stream.generate(() -> new AtomicIntegerArray(METHOD_MAX_ID)).limit(CLASS_MAX_ID).toArray(AtomicIntegerArray[]::new);
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

        disruptor.handleEventsWith(this);
        disruptor.start();

        new Timer(true).schedule(
                new TimerTask() {
                    @Override
                    public void run() {
                        resetQuotas();
                    }
                },
                0,
                TimeUnit.MINUTES.toMillis(1)
        );
    }

    private void reloadClasses() {
        reloadClasses(smithClasses.keySet());
    }

    private void reloadClasses(Collection<String> classes) {
        Class<?>[] loadedClasses = inst.getAllLoadedClasses();
        Class<?>[] cls = Arrays.stream(loadedClasses).filter(c -> classes.contains(c.getName())).toArray(Class<?>[]::new);

        SmithLogger.logger.info("reload: " + Arrays.toString(cls));

        try {
            inst.retransformClasses(cls);
        } catch (UnmodifiableClassException e) {
            SmithLogger.exception(e);
        }
    }

    public void detect(int classID, int methodID, Object[] args) {
        SmithBlock block = smithBlocks.get(new ImmutablePair<>(classID, methodID));

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

    public void trace(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if (!clientConnected)
            return;

        if (classID >= CLASS_MAX_ID || methodID >= METHOD_MAX_ID)
            return;

        while (true) {
            int quota = smithQuotas[classID].get(methodID);

            if (quota <= 0)
                return;

            if (smithQuotas[classID].compareAndSet(methodID, quota, quota - 1))
                break;
        }

        RingBuffer<SmithTrace> ringBuffer = disruptor.getRingBuffer();

        try {
            long sequence = ringBuffer.tryNext();

            SmithTrace smithTrace = ringBuffer.get(sequence);

            smithTrace.setClassID(classID);
            smithTrace.setMethodID(methodID);
            smithTrace.setBlocked(blocked);
            smithTrace.setRet(ret);
            smithTrace.setArgs(args);
            smithTrace.setStackTrace(Thread.currentThread().getStackTrace());

            ringBuffer.publish(sequence);
        } catch (InsufficientCapacityException ignored) {

        }
    }

    @Override
    public void onEvent(SmithTrace smithTrace, long sequence, boolean endOfBatch) {
        SmithFilter filter = smithFilters.get(new ImmutablePair<>(smithTrace.getClassID(), smithTrace.getMethodID()));

        if (filter == null) {
            probeClient.write(Operate.TRACE, smithTrace);
            return;
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
            return;

        if (exclude.length > 0 && Arrays.stream(exclude).anyMatch(pred))
            return;

        probeClient.write(Operate.TRACE, smithTrace);
    }

    private void resetQuotas() {
        for (int i = 0; i < CLASS_MAX_ID; i++) {
            for (int j = 0; j < METHOD_MAX_ID; j++) {
                Integer quota = smithLimits.get(new ImmutablePair<>(i, j));

                if (quota == null) {
                    smithQuotas[i].set(j, DEFAULT_QUOTA);
                    continue;
                }

                smithQuotas[i].set(j, quota);
            }
        }
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (disable)
            return null;

        Type classType = Type.getObjectType(className);
        SmithClass smithClass = smithClasses.get(classType.getClassName());

        if (smithClass == null)
            return null;

        SmithLogger.logger.info("transform: " + classType.getClassName());

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
        disable = action == Action.STOP.ordinal();
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

        probeClient.write(Operate.DETECT, Collections.singletonMap("jars", smithJars));
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

    @Override
    public void onLimit(SmithLimit[] limits) {
        smithLimits.clear();

        for (SmithLimit limit : limits) {
            smithLimits.put(
                    new ImmutablePair<>(limit.getClassID(), limit.getMethodID()),
                    limit.getQuota()
            );
        }
    }

    @Override
    public void onPatch(SmithPatch[] patches) {
        for (SmithPatch smithPatch : patches) {
            if (smithPatches.containsKey(smithPatch.getClassName()))
                continue;

            try (URLClassLoader loader = new URLClassLoader(new URL[]{smithPatch.getUrl()})) {
                Patch patch = loader.loadClass(smithPatch.getClassName())
                        .asSubclass(Patch.class)
                        .getConstructor(Instrumentation.class)
                        .newInstance(inst);

                patch.install();

                smithPatches.put(smithPatch.getClassName(), patch);
            } catch (IOException | ClassNotFoundException | NoSuchMethodException | InvocationTargetException |
                     InstantiationException | IllegalAccessException e) {
                SmithLogger.exception(e);
            }
        }

        Set<String> active = Arrays.stream(patches).map(SmithPatch::getClassName).collect(Collectors.toSet());

        smithPatches.keySet().stream().filter(name -> !active.contains(name)).forEach(
                name -> {
                    Patch patch = smithPatches.remove(name);

                    if (patch == null)
                        return;

                    patch.uninstall();
                }
        );
    }
}
