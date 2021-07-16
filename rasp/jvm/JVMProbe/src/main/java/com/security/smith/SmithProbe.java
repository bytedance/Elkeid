package com.security.smith;

import com.security.smith.asm.SmithClassNode;
import com.security.smith.asm.SmithClassWriter;
import com.security.smith.client.Operate;
import com.security.smith.client.ProbeClient;
import com.security.smith.client.ProbeNotify;
import com.security.smith.log.SmithLogger;
import com.security.smith.type.SmithClass;
import com.security.smith.type.SmithJar;

import com.security.smith.type.SmithTrace;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
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
        for (String className : classes) {
            try {
                Class<?> clazz = Class.forName(className, true, ClassLoader.getSystemClassLoader());
                inst.retransformClasses(clazz);
                SmithLogger.logger.info("reload: " + clazz);
            } catch (ClassNotFoundException e) {
                SmithLogger.logger.info("class not found: " + className);
            } catch (UnmodifiableClassException e) {
                SmithLogger.exception(e);
            }
        }
    }

    public void trace(int classID, int methodID, Object[] args, Object ret) {
        if (!clientConnected)
            return;

        SmithTrace smithTrace = new SmithTrace();

        smithTrace.setClassID(classID);
        smithTrace.setMethodID(methodID);
        smithTrace.setRet(ret);
        smithTrace.setArgs(args);
        smithTrace.setStackTrace(Thread.currentThread().getStackTrace());

        traceQueue.offer(smithTrace);
    }

    private void probeTraceThread() {
        SmithLogger.logger.info("probe trace thread start");

        while (true) {
            try {
                SmithTrace smithTrace = traceQueue.take();
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

        SmithClass smithClass = smithClasses.get(className.replace("/", "."));

        if (smithClass == null)
            return null;

        SmithLogger.logger.info("transform: " + className);

        ClassReader classReader = new ClassReader(classfileBuffer);
        SmithClassNode classNode = new SmithClassNode(Opcodes.ASM8);

        classNode.setProbeName(this.getClass().getName());
        classNode.setClassID(smithClass.getId());
        classNode.setMethodMap(smithClass.getMethods().stream()
                .collect(Collectors.toMap(method -> method.getName() + method.getDesc(), method -> method)));

        classReader.accept(classNode, ClassReader.SKIP_FRAMES);

        try {
            ClassWriter classWriter = new SmithClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            classNode.accept(classWriter);

            SmithLogger.logger.info("transform finish");

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
}
