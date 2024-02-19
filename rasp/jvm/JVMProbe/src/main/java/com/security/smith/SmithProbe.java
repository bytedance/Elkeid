package com.security.smith;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
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
    private final Map<Pair<Integer, Integer>, List<Long>> records;
    private final Map<Pair<Integer, Integer>, List<Long>> recordsTotal;
    private final Map<Pair<Integer, Integer>, Long> hooktimeRecords;
    private final Map<Pair<Integer, Integer>, Long> runtimeRecords;
    private final Map<Pair<Integer, Integer>, Filter> filters;
    private final Map<Pair<Integer, Integer>, List<Block>> blocks;
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
        records = new HashMap<>();
        recordsTotal = new HashMap<>();
        hooktimeRecords = new HashMap<>();
        runtimeRecords = new HashMap<>();

        heartbeat = new Heartbeat();
        client = new Client(this);
        disruptor = new Disruptor<>(Trace::new, TRACE_BUFFER_SIZE, DaemonThreadFactory.INSTANCE);
        quotas = Stream.generate(() -> new AtomicIntegerArray(METHOD_MAX_ID)).limit(CLASS_MAX_ID).toArray(AtomicIntegerArray[]::new);
    }

    public void setInst(Instrumentation inst) {
        this.inst = inst;
    }

    public void init() {
        ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
        InputStream inputStream = this.getClass().getResourceAsStream("/class.yaml");

        try {
            for (SmithClass smithClass : objectMapper.readValue(inputStream, SmithClass[].class))
                smithClasses.put(smithClass.getName(), smithClass);
        } catch (IOException e) {
            SmithLogger.exception(e);
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

        new Timer(true).schedule(
            new TimerTask() {
                @Override
                public void run() {
                    show();
                }
            },
            TimeUnit.SECONDS.toMillis(5),
            TimeUnit.SECONDS.toMillis(10)
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

    public boolean surplus(int classID, int methodID) {
        if (classID >= CLASS_MAX_ID || methodID >= METHOD_MAX_ID)
            return false;

        while (true) {
            int quota = quotas[classID].get(methodID);

            if (quota <= 0)
                return false;

            if (quotas[classID].compareAndSet(methodID, quota, quota - 1))
                break;
        }

        return true;
    }

    public Trace newTrace(int classID, int methodID, Object[] args) {
        Trace trace = new Trace();

        trace.setClassID(classID);
        trace.setMethodID(methodID);
        trace.setArgs(args);
        trace.setStackTrace(Thread.currentThread().getStackTrace());

        return trace;
    }

    public void detect(Trace trace) {
        List<Block> policies = blocks.get(new ImmutablePair<>(trace.getClassID(), trace.getMethodID()));

        if (policies == null)
            return;

        for (Block block : policies) {
            MatchRule[] rules = block.getRules();

            if (rules.length > 0 && Arrays.stream(block.getRules()).noneMatch(rule -> {
                if (rule.getIndex() >= trace.getArgs().length)
                    return false;

                return Pattern.compile(rule.getRegex()).matcher(trace.getArgs()[rule.getIndex()].toString()).find();
            }))
                continue;

            StackFrame stackFrame = block.getStackFrame();

            if (stackFrame == null) {
                trace.setBlocked(true);
                trace.setPolicyID(block.getPolicyID());
                throw new SecurityException("API blocked by RASP");
            }

            StackTraceElement[] elements = trace.getStackTrace();

            if (elements.length <= 2)
                continue;

            String[] frames = Arrays.stream(Arrays.copyOfRange(elements, 2, elements.length))
                    .map(StackTraceElement::toString)
                    .toArray(String[]::new);

            Predicate<String> pred = keyword -> Arrays.stream(frames).anyMatch(frame -> Pattern.compile(keyword).matcher(frame).find());

            if (stackFrame.getOperator() == StackFrame.Operator.OR && Arrays.stream(stackFrame.getKeywords()).anyMatch(pred)) {
                trace.setBlocked(true);
                trace.setPolicyID(block.getPolicyID());
                throw new SecurityException("API blocked by RASP");
            }

            if (stackFrame.getOperator() == StackFrame.Operator.AND && Arrays.stream(stackFrame.getKeywords()).allMatch(pred)) {
                trace.setBlocked(true);
                trace.setPolicyID(block.getPolicyID());
                throw new SecurityException("API blocked by RASP");
            }
        }
    }

    public void post(Trace trace) {
        RingBuffer<Trace> ringBuffer = disruptor.getRingBuffer();

        try {
            long sequence = ringBuffer.tryNext();

            Trace t = ringBuffer.get(sequence);

            t.setClassID(trace.getClassID());
            t.setMethodID(trace.getMethodID());
            t.setBlocked(trace.isBlocked());
            t.setPolicyID(trace.getPolicyID());
            t.setRet(trace.getRet());
            t.setArgs(trace.getArgs());
            t.setStackTrace(trace.getStackTrace());

            ringBuffer.publish(sequence);
        } catch (InsufficientCapacityException ignored) {

        }
    }

    private Long tp(List<Long> times, double percent) {
        return times.get((int)(percent / 100 * times.size() - 1));
    }

    private void show() {
        synchronized (records) {
            SmithLogger.logger.info("=================== statistics ===================");

            records.forEach((k, v) -> {
                Collections.sort(v);

                List<Long> tv = recordsTotal.get(new ImmutablePair<>(k.getLeft(), k.getRight()));

                Collections.sort(tv);

                Long hooktime = hooktimeRecords.get(new ImmutablePair<>(k.getLeft(), k.getRight()));
                Long runtime = runtimeRecords.get(new ImmutablePair<>(k.getLeft(), k.getRight()));

                SmithLogger.logger.info(
                        String.format(
                                "class: %d method: %d count: %d tp50: %d tp90: %d tp95: %d tp99: %d tp99.99: %d max: %d total-max:%d hooktime:%d runtime:%d",
                                k.getLeft(),
                                k.getRight(),
                                v.size(),
                                tp(v, 50),
                                tp(v, 90),
                                tp(v, 95),
                                tp(v, 99),
                                tp(v, 99.99),
                                v.get(v.size() - 1),
                                tv.get(tv.size() - 1),
                                hooktime,
                                runtime
                        )
                );
            });
        }
    }

    public void record(int classID, int methodID, long time,long totaltime) {
        synchronized (records) {
            records.computeIfAbsent(new ImmutablePair<>(classID, methodID), k -> new ArrayList<>()).add(time);
        }

        synchronized (recordsTotal) {
            recordsTotal.computeIfAbsent(new ImmutablePair<>(classID, methodID), k -> new ArrayList<>()).add(totaltime);
        }

        synchronized (hooktimeRecords) {
            hooktimeRecords.computeIfAbsent(new ImmutablePair<>(classID, methodID), k -> time);
            hooktimeRecords.computeIfPresent(new ImmutablePair<>(classID, methodID),(k,v) -> v+time);
        }

        synchronized (runtimeRecords) {
            runtimeRecords.computeIfAbsent(new ImmutablePair<>(classID, methodID), k -> totaltime);
            runtimeRecords.computeIfPresent(new ImmutablePair<>(classID, methodID),(k,v) -> v+totaltime);
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

        ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());

        try {
            for (SmithClass smithClass : objectMapper.readValue(config, SmithClass[].class))
                smithClasses.put(smithClass.getName(), smithClass);
        } catch (JsonProcessingException e) {
            SmithLogger.exception(e);
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

            URL url = codeSource.getLocation();

            if (url == null)
                continue;

            jar.setPath(url.toString());

            if (jars.contains(jar))
                continue;

            Package pkg = cl.getPackage();

            if (pkg == null)
                continue;

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
            blocks.computeIfAbsent(
                    new ImmutablePair<>(block.getClassID(), block.getMethodID()),
                    k -> new ArrayList<>()
            ).add(block);
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
