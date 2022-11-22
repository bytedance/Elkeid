package com.security.smith;

import com.lmax.disruptor.EventHandler;
import com.lmax.disruptor.InsufficientCapacityException;
import com.lmax.disruptor.RingBuffer;
import com.lmax.disruptor.dsl.Disruptor;
import com.lmax.disruptor.util.DaemonThreadFactory;
import com.security.smith.asm.SmithClassVisitor;
import com.security.smith.asm.SmithClassWriter;
import com.security.smith.client.Operate;
import com.security.smith.client.Client;
import com.security.smith.client.MessageHandler;
import com.security.smith.client.message.*;
import com.security.smith.log.SmithLogger;
import com.security.smith.module.Patcher;
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

public class SmithProbe implements ClassFileTransformer, MessageHandler, EventHandler<Trace> {
    private static final SmithProbe ourInstance = new SmithProbe();
    private static final int TRACE_BUFFER_SIZE = 1024;
    private static final int CLASS_MAX_ID = 30;
    private static final int METHOD_MAX_ID = 20;
    private static final int DEFAULT_QUOTA = 12000;

    private Boolean disable;
    private Instrumentation inst;
    private final Client client;
    private final Heartbeat heartbeat;
    private final Disruptor<Trace> disruptor;
    private final Map<String, SmithClass> smithClasses;
    private final Map<String, Patcher> patchers;
    private final Map<Pair<Integer, Integer>, Filter> filters;
    private final Map<Pair<Integer, Integer>, Block> blocks;
    private final Map<Pair<Integer, Integer>, Integer> limits;
    private final AtomicIntegerArray[] quotas;

    enum Action {
        STOP,
        START
    }

    public static SmithProbe getInstance() {
        return ourInstance;
    }

    public SmithProbe() {
        disable = false;

        smithClasses = new ConcurrentHashMap<>();
        patchers = new ConcurrentHashMap<>();
        filters = new ConcurrentHashMap<>();
        blocks = new ConcurrentHashMap<>();
        limits = new ConcurrentHashMap<>();

        heartbeat = new Heartbeat();
        client = new Client(this);
        disruptor = new Disruptor<>(Trace::new, TRACE_BUFFER_SIZE, DaemonThreadFactory.INSTANCE);
        quotas = Stream.generate(() -> new AtomicIntegerArray(METHOD_MAX_ID)).limit(CLASS_MAX_ID).toArray(AtomicIntegerArray[]::new);
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

        Thread clientThread = new Thread(client::start);

        clientThread.setDaemon(true);
        clientThread.start();

        disruptor.handleEventsWith(this);
        disruptor.start();

        new Timer(true).schedule(
                new TimerTask() {
                    @Override
                    public void run() {
                        onDetect();
                    }
                },
                TimeUnit.MINUTES.toMillis(1)
        );

        new Timer(true).schedule(
                new TimerTask() {
                    @Override
                    public void run() {
                        onTimer();
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
        Block block = blocks.get(new ImmutablePair<>(classID, methodID));

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
        if (classID >= CLASS_MAX_ID || methodID >= METHOD_MAX_ID)
            return;

        while (true) {
            int quota = quotas[classID].get(methodID);

            if (quota <= 0)
                return;

            if (quotas[classID].compareAndSet(methodID, quota, quota - 1))
                break;
        }

        RingBuffer<Trace> ringBuffer = disruptor.getRingBuffer();

        try {
            long sequence = ringBuffer.tryNext();

            Trace trace = ringBuffer.get(sequence);

            trace.setClassID(classID);
            trace.setMethodID(methodID);
            trace.setBlocked(blocked);
            trace.setRet(ret);
            trace.setArgs(args);
            trace.setStackTrace(Thread.currentThread().getStackTrace());

            ringBuffer.publish(sequence);
        } catch (InsufficientCapacityException ignored) {

        }
    }

    @Override
    public void onEvent(Trace trace, long sequence, boolean endOfBatch) {
        Filter filter = filters.get(new ImmutablePair<>(trace.getClassID(), trace.getMethodID()));

        if (filter == null) {
            client.write(Operate.TRACE, trace);
            return;
        }

        Predicate<MatchRule> pred = rule -> {
            Object[] args = trace.getArgs();

            if (rule.getIndex() >= args.length)
                return false;

            return Pattern.compile(rule.getRegex()).matcher(args[rule.getIndex()].toString()).find();
        };

        MatchRule[] include = filter.getInclude();
        MatchRule[] exclude = filter.getExclude();

        if (include.length > 0 && Arrays.stream(include).noneMatch(pred))
            return;

        if (exclude.length > 0 && Arrays.stream(exclude).anyMatch(pred))
            return;

        client.write(Operate.TRACE, trace);
    }

    private void onTimer() {
        client.write(Operate.HEARTBEAT, heartbeat);

        for (int i = 0; i < CLASS_MAX_ID; i++) {
            for (int j = 0; j < METHOD_MAX_ID; j++) {
                Integer quota = limits.get(new ImmutablePair<>(i, j));

                if (quota == null) {
                    quotas[i].set(j, DEFAULT_QUOTA);
                    continue;
                }

                quotas[i].set(j, quota);
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

        Set<Jar> jars = new HashSet<>();

        for (Class<?> cl : inst.getAllLoadedClasses()) {
            CodeSource codeSource = cl.getProtectionDomain().getCodeSource();

            if (codeSource == null)
                continue;

            Jar jar = new Jar();
            jar.setPath(codeSource.getLocation().toString());

            if (jars.contains(jar))
                continue;

            Package pkg = cl.getPackage();

            jar.setSpecificationTitle(pkg.getSpecificationTitle());
            jar.setSpecificationVersion(pkg.getSpecificationVersion());
            jar.setImplementationTitle(pkg.getImplementationTitle());
            jar.setImplementationVersion(pkg.getImplementationVersion());

            jars.add(jar);
        }

        client.write(Operate.DETECT, Collections.singletonMap("jars", jars));
    }

    @Override
    public void onFilter(FilterConfig config) {
        filters.clear();

        for (Filter filter : config.getFilters()) {
            filters.put(
                    new ImmutablePair<>(filter.getClassID(), filter.getMethodID()),
                    filter
            );
        }

        heartbeat.setFilter(config.getUUID());
    }

    @Override
    public void onBlock(BlockConfig config) {
        blocks.clear();

        for (Block block : config.getBlocks()) {
            blocks.put(
                    new ImmutablePair<>(block.getClassID(), block.getMethodID()),
                    block
            );
        }

        heartbeat.setBlock(config.getUUID());
    }

    @Override
    public void onLimit(LimitConfig config) {
        limits.clear();

        for (Limit limit : config.getLimits()) {
            limits.put(
                    new ImmutablePair<>(limit.getClassID(), limit.getMethodID()),
                    limit.getQuota()
            );
        }

        heartbeat.setLimit(config.getUUID());
    }

    @Override
    public void onPatch(PatchConfig config) {
        for (Patch patch : config.getPatches()) {
            SmithLogger.logger.info("install patch: " + patch.getClassName());

            if (patchers.containsKey(patch.getClassName())) {
                SmithLogger.logger.info("ignore installed patch: " + patch.getClassName());
                continue;
            }

            try (URLClassLoader loader = new URLClassLoader(new URL[]{patch.getUrl()})) {
                Patcher patcher = loader.loadClass(patch.getClassName())
                        .asSubclass(Patcher.class)
                        .getConstructor(Instrumentation.class)
                        .newInstance(inst);

                patcher.install();

                patchers.put(patch.getClassName(), patcher);
            } catch (IOException | ClassNotFoundException | NoSuchMethodException | InvocationTargetException |
                     InstantiationException | IllegalAccessException e) {
                SmithLogger.exception(e);
            }
        }

        Set<String> active = Arrays.stream(config.getPatches()).map(Patch::getClassName).collect(Collectors.toSet());

        patchers.keySet().stream().filter(name -> !active.contains(name)).forEach(
                name -> {
                    SmithLogger.logger.info("uninstall patch: " + name);

                    Patcher patcher = patchers.remove(name);

                    if (patcher == null)
                        return;

                    patcher.uninstall();
                }
        );

        heartbeat.setPatch(config.getUUID());
    }
}
