package com.security.smith;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.lmax.disruptor.EventHandler;

import com.lmax.disruptor.dsl.Disruptor;
import com.lmax.disruptor.util.DaemonThreadFactory;
import com.security.smith.asm.SmithClassVisitor;
import com.security.smith.asm.SmithClassWriter;
import com.security.smith.client.message.*;

import com.security.smith.common.SmithHandler;
import com.security.smith.common.SmithTools;
import com.security.smith.log.AttachInfo;
import com.security.smith.log.SmithLogger;
import com.security.smith.module.Patcher;
import com.security.smith.type.*;
import com.security.smith.client.*;

import javassist.ClassPool;
import javassist.CtClass;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.objectweb.asm.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;

import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.security.ProtectionDomain;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import java.io.File;
import java.io.FileOutputStream;
import java.security.CodeSource;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarFile;



public class SmithProbe implements ClassFileTransformer, MessageHandler, EventHandler<Trace> {
    private static final SmithProbe ourInstance = new SmithProbe();
    private static final int TRACE_BUFFER_SIZE = 1024;

    private Boolean disable;
    private Boolean scanswitch;
    private Instrumentation inst;
    private final Client client;
    private final Heartbeat heartbeat;
    
    private final Map<String, SmithClass> smithClasses;
    private final Map<String, Patcher> patchers;
    private final Map<Pair<Integer, Integer>, List<Long>> records;
    private final Map<Pair<Integer, Integer>, List<Long>> recordsTotal;
    private final Map<Pair<Integer, Integer>, Long> hooktimeRecords;
    private final Map<Pair<Integer, Integer>, Long> runtimeRecords;
    private final Map<Pair<Integer, Integer>, Filter> filters;
    private final Map<Pair<Integer, Integer>, Block> blocks;
    private final Map<Pair<Integer, Integer>, Integer> limits;
    private final Disruptor<Trace> disruptor;
    
    private final Rule_Mgr    rulemgr;
    private final Rule_Config ruleconfig;
    private SmithProbeProxy smithProxy;

    enum Action {
        STOP,
        START
    }

    public static SmithProbe getInstance() {
        return ourInstance;
    }

    public SmithProbe() {
        disable = false;
        scanswitch = true;

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
        rulemgr = new Rule_Mgr();
        ruleconfig = new Rule_Config(rulemgr);
    }

    public void setInst(Instrumentation inst) {
        this.inst = inst;
    }

    private boolean isBypassHookClass(String className) {

        if(SmithTools.isGlassfish() && SmithTools.getMajorVersion() > 5) {
            /*
             * In versions after GlassFish 5 (not including GlassFish 5), 
             * not hooking java.io.File will cause the JVM process to crash directly if hooked.
             * 
             */
            if(className.equals("java.io.File")) {
                return true;
            }
        }

        return false;
    }

    public void init() {
        ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
        InputStream inputStream = this.getClass().getResourceAsStream("/class.yaml");

        try {
            for (SmithClass smithClass : objectMapper.readValue(inputStream, SmithClass[].class)) {
                if(!isBypassHookClass(smithClass.getName())) {
                    smithClasses.put(smithClass.getName(), smithClass);
                }
            }
        } catch (IOException e) {
            SmithLogger.exception(e);
        }
    }

    public void start() {
        SmithLogger.logger.info("probe start");
        AttachInfo.info();

        SmithLogger.logger.info("init ClassUploadTransformer");
        ClassUploadTransformer.getInstance().start(client, inst);

        

        Thread clientThread = new Thread(client::start);

        disruptor.handleEventsWith(this);
        disruptor.start();
    
        clientThread.setDaemon(true);
        clientThread.start();

        new Timer(true).schedule(
                new TimerTask() {
                    @Override
                    public void run() {
                        onDetect();
                    }
                },
                TimeUnit.MINUTES.toMillis(1)
        );
        smithProxy = SmithProbeProxy.getInstance();
        SmithProbeProxy.getInstance().setReflectField();
        SmithProbeProxy.getInstance().setClient(client);
        SmithProbeProxy.getInstance().setDisruptor(disruptor);
        SmithProbeProxy.getInstance().setReflectMethod();
        new Timer(true).schedule(
                new TimerTask() {
                    @Override
                    public void run() {
                        smithProxy.onTimer();
                    }
                },
                0,
                TimeUnit.MINUTES.toMillis(1)
        );
    }

    private void reloadClasses() {
        reloadClasses(smithClasses.keySet());
    }


    private String getJarPath(Class<?> clazz) {
        CodeSource codeSource = clazz.getProtectionDomain().getCodeSource();
        if (codeSource != null) {
            URL location = codeSource.getLocation();
            try {
                File file = new File(location.toURI());
                return file.getAbsolutePath();
            } catch (Exception e) {
                SmithLogger.exception(e);
            }
        }
        return null;
    }

    private String[] addJarclassns = {
        "org.apache.felix.framework.BundleWiringImpl$BundleClassLoader"
    };
    
    private Set<String> addedJarset = Collections.synchronizedSet(new HashSet<>());

    public void checkNeedAddJarPath(Class<?> clazz,Instrumentation inst) {
        try {
            String cn = clazz.getName();
            for (String name : addJarclassns) {
                if(cn.equals(name)) {
                    try {
                        String jarFile = getJarPath(clazz);
                        if(jarFile != null && !addedJarset.contains(jarFile)) {
                            SmithLogger.logger.info("add "+ name + " jarpath:"+jarFile);
                            inst.appendToSystemClassLoaderSearch(new JarFile(jarFile));
                            addedJarset.add(jarFile);
                        }
                    }catch(Exception e) {
                        SmithLogger.exception(e);
                    }
                }
            }
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }
    }

    public void checkNeedAddJarPaths(Class<?>[] cls,Instrumentation inst) {
        for (Class<?> cx : cls) {
            checkNeedAddJarPath(cx,inst);
        } 
    }

    private void reloadClasses(Collection<String> classes) {
        Class<?>[] loadedClasses = inst.getAllLoadedClasses();
        Class<?>[] cls = Arrays.stream(loadedClasses).filter(c -> classes.contains(c.getName())).toArray(Class<?>[]::new);

        SmithLogger.logger.info("reload: " + Arrays.toString(cls));
        //System.out.println("reload Class:"+cls.getClass().getName());

        checkNeedAddJarPaths(cls,inst);

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

    @Override
    public void onEvent(Trace trace, long sequence, boolean endOfBatch) {
        Filter filter = filters.get(new ImmutablePair<>(trace.getClassID(), trace.getMethodID()));

        if (filter == null) {
            client.write(Operate.TRACE, trace);
            return;
        }

        Predicate<MatchRule> pred = rule -> {
            Object[] args = trace.getArgs();

            if (rule.getIndex() >= args.length || rule.getRegex().isEmpty() || args[rule.getIndex()] == null)
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

    public void printClassfilter(ClassFilter data) {
            /* 
        SmithLogger.logger.info("className:" + data.getClassName());
        SmithLogger.logger.info("classPath:" + data.getClassPath());
        SmithLogger.logger.info("interfaceName:" + data.getInterfacesName());
        SmithLogger.logger.info("classLoaderName:" + data.getClassLoaderName());
        SmithLogger.logger.info("parentClassName:" + data.getParentClassName());
        */

        SmithLogger.logger.info("------------------------------------------------------------------------");
        SmithLogger.logger.info("className:" + data.getClassName());
        SmithLogger.logger.info("classPath:" + data.getClassPath());
        SmithLogger.logger.info("interfaceName:" + data.getInterfacesName());
        SmithLogger.logger.info("classLoaderName:" + data.getClassLoaderName());
        SmithLogger.logger.info("parentClassName:" + data.getParentClassName());
        SmithLogger.logger.info("parentClassLoaderName:" + data.getParentClassLoaderName());

    }

    public InputStream byteArrayToInputStream(byte[] bytes) throws IOException {
        if(bytes == null) {
            return null;
        }

        ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
        
        return inputStream;
    }

    private void checkClassFilter(ClassLoader loader, String className, byte[] classfileBuffer) {
        CtClass ctClass = null;

        try {
            if (className == null && classfileBuffer == null) {
                SmithLogger.logger.info("nononono className == null && classfileBuffer == null");
                return ;
            }

            String className_std = "";
         
            ClassPool pool = ClassPool.getDefault();
            
            if (className != null) {
                className_std = className;
                if (className.startsWith("com/security/smith") || className.startsWith("rasp/")) {
                    return ;
                }

                ctClass = pool.makeClass(className);
            }
            else {
                className_std = "";

                InputStream inputS = byteArrayToInputStream(classfileBuffer);

                ctClass = pool.makeClass(inputS);
            }

            if (ctClass == null) {
                return ;
            } else {
                className_std = ctClass.getName();
            }
            
            if (className_std != "") {
                className_std = className_std.replace("/", ".");
            }

            ClassFilter classFilter = new ClassFilter();
            if (loader != null) {
                classFilter.setClassLoaderName(loader.getClass().getName());
            }
            classFilter.setClassName(className_std);
            

            try {
                if (!ctClass.isInterface()) {
                    classFilter.setInterfacesName(SmithHandler.getCtClassInterfaces(ctClass));
                }    
                classFilter.setClassPath(SmithHandler.getCtClassPath(ctClass));
                CtClass superClass = null;
                try {
                    superClass = ctClass.getSuperclass();
                } catch(Exception e) {
                    // SmithLogger.exception(e);
                }

                String superClassName = superClass != null ? superClass.getName() : "";
                classFilter.setParentClassName(superClassName);
        
                if (superClass != null) {
                    ClassLoader parentClassLoader = superClass.getClassPool().getClassLoader();
                    String parentClassLoaderName = parentClassLoader != null ? parentClassLoader.getClass().getName() : "";
                    classFilter.setParentClassLoaderName(parentClassLoaderName);
                }
            } catch (Exception e) {
                SmithLogger.exception(e);
            }
           /* 
            try {
                printClassfilter(classFilter);
            }
            catch(Exception e) {
            }
*/
            long rule_id = rulemgr.matchRule(classFilter);
            if(rule_id != -1) {
               // System.out.println("Hit---------------------RuleId:" + rule_id);

                classFilter.setRuleId(rule_id);
                classFilter.setTransId();
                classFilter.setStackTrace(Thread.currentThread().getStackTrace());

                client.write(Operate.SCANCLASS, classFilter);
                SmithLogger.logger.info("send metadata: " + classFilter.toString());
                Thread.sleep(1000);
                sendByte(classfileBuffer, classFilter.getTransId());
            }
        } catch(Exception e) {
            SmithLogger.exception(e);
        }
        finally {
            if(ctClass != null) {
                ctClass.detach();
            }
        }
    }

    boolean hasExceptionHook(Map<String, SmithMethod> methodMap) {
        Iterator<Map.Entry<String, SmithMethod>> iterator = methodMap.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, SmithMethod> entry = iterator.next();
            SmithMethod value = entry.getValue();
            String exceptionHookName = value.getExceptionHook();
            if(exceptionHookName != null && exceptionHookName.length() > 1 && exceptionHookName != "") {
                return true;
            }
        }

        return false;
    }

   
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
         if (disable)
            return null;

        // if(scanswitch) {
        //     checkClassFilter(loader, className,classfileBuffer);
        // }

        Type classType = null;
        SmithClass smithClass = null;
        try {
            classType = Type.getObjectType(className);
            smithClass = smithClasses.get(classType.getClassName());
        } catch (Exception e) {
            //SmithLogger.exception(e);
        }

        if (smithClass == null)  {
            
            ClassReader cr = new ClassReader(classfileBuffer);

            if (className == null) {
                className = cr.getClassName();
                classType = Type.getObjectType(className);
            }
            String[] interfaces = cr.getInterfaces();
            String superClass = cr.getSuperName();

            try {
                String[] combined;
                if (superClass != null) {
                    combined = new String[interfaces.length + 1];
                    System.arraycopy(interfaces, 0, combined, 0, interfaces.length);
                    combined[interfaces.length] = superClass;
                } else {
                    combined = interfaces;
                }

                for (String interName : combined) {
                    if (SmithHandler.checkInterfaceNeedTran(interName)) {
                        Type interfaceType = Type.getObjectType(interName);
                        smithClass = smithClasses.get(interfaceType.getClassName());
                        break;
                    }
                }
            } catch (Throwable e) {
                SmithLogger.exception(e);
            }
            
            if (smithClass == null) {
                return null;
            }
        }

        try {
            Map<String, SmithMethod> methodMap = smithClass.getMethods().stream().collect(Collectors.toMap(method -> method.getName() + method.getDesc(), method -> method));
            
            SmithLogger.logger.info("transform: " + classType.getClassName());
            ClassReader classReader = new ClassReader(classfileBuffer);

            ClassWriter classWriter;
            if(!hasExceptionHook(methodMap)) {
                classWriter = new SmithClassWriter(ClassWriter.COMPUTE_MAXS);
            }
            else {
                classWriter = new SmithClassWriter(ClassWriter.COMPUTE_FRAMES);
            }

            ClassVisitor classVisitor = new SmithClassVisitor(
                    Opcodes.ASM9,
                    classWriter,
                    smithClass.getId(),
                    classType,
                    methodMap
            );

            classReader.accept(classVisitor, ClassReader.EXPAND_FRAMES);      
            return classWriter.toByteArray();
        } catch (Throwable e) {
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
        if (config == null || config.getPatches() == null || config.getPatches().length == 0) {
            SmithLogger.logger.info("patch may not be download, so not update heartbeat");
            return ;
        }
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


    @Override
    public boolean setRuleVersion(Rule_Version ruleVersion) {
        boolean bresult = false;

        try {
            bresult = ruleconfig.setVersion(ruleVersion.getRule_version());
            heartbeat.setClassFilterVersion(ruleVersion.getClass_filter_version());
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        return bresult;
    }

    @Override
    public boolean OnAddRule(Rule_Data ruleData) {
        boolean bresult = false;

        try {
            bresult = ruleconfig.addRuleData(ruleData);
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        return bresult;
    }

    @Override
    public boolean OnAddRule(String rulejson) {
        boolean bresult = false;

        try {
            bresult = ruleconfig.setRuleConfig(rulejson);
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        return bresult;
    }

    
    /* scan all class */
    @Override
    public void onScanAllClass() {
        if (scanswitch == false) {
            return;
        }
        scanswitch = false;

        try {
            Class<?>[] loadedClasses = inst.getAllLoadedClasses();

            for (Class<?> clazz : loadedClasses) {
                try {
                    
                    String className = clazz.getName();
                    if (className.startsWith("rasp.") || className.startsWith("com.security.smith") || className.startsWith("java.lang.invoke.LambdaForm")) {
                        continue;
                    }

                    if(classIsSended(clazz)) {
                        continue;
                    }
                    
                    ClassFilter classFilter = new ClassFilter();
                    
                    SmithHandler.queryClassFilter(clazz, classFilter);
                    long rule_id = -1;
                    if (!SmithHandler.checkClassMemshell(clazz)) {
                        rule_id = rulemgr.matchRule(classFilter);
                        if (rule_id == -1)
                            continue;
                    }
                    classFilter.setTransId();
                    classFilter.setRuleId(rule_id);
                    classFilter.setStackTrace(Thread.currentThread().getStackTrace());

                    client.write(Operate.SCANCLASS, classFilter);
                    SmithLogger.logger.info("send metadata: " + classFilter.toString());
                    sendClass(clazz, classFilter.getTransId());

                } catch(Exception e) {
                    SmithLogger.exception(e);
                }
            }
        } catch(Exception e) {
            SmithLogger.exception(e);
        }
        finally {
            scanswitch = true;
            SmithLogger.logger.info("scan all class finished");
        }
    }

    /*
     * send class file
     */
    public void sendClass(Class<?> clazz, String transId) {
        if (clazz == null || transId == null) {
            return;
        }
        try {
            ClassUploadTransformer.getInstance().sendClass(clazz, transId);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    public boolean classIsSended(Class<?> clazz) {
        try {
            return ClassUploadTransformer.getInstance().classIsSended(clazz.hashCode());
        } catch (Exception e) {
            SmithLogger.exception(e);
        }

        return false;
    }

    /*
     * send CtClass file 
     */
    private void sendByte(byte[] data, String transId) {
        if (data == null) {
            return;
        }
        int length = data.length;
        ClassUpload classUpload = new ClassUpload();
        classUpload.setTransId(transId);

        // client.write(Operate.CLASSDUMP, classUpload);

        // int packetSize = 1024; \
        // int totalPackets = (data.length + packetSize - 1) / packetSize;
        //for (int i = 0; i < totalPackets; i++) {
            //int offset = i * packetSize;
            classUpload.setByteTotalLength(length);
            //classUpload.setByteOffset(offset);
            classUpload.setByteLength(length);
            //int send_length = Math.min(packetSize, data.length - offset);
            classUpload.setClassData(data);

            client.write(Operate.CLASSUPLOAD, classUpload);
            SmithLogger.logger.info("send classdata: " + classUpload.toString());
        //}
    }

    public Heartbeat getHeartbeat() {
        return heartbeat;
    }

    public void addDisacrdCount() {
        int discrad_count = this.heartbeat.getDiscardCount();
        discrad_count++;
        this.heartbeat.setDiscardCount(discrad_count);
    }

    public Map<Pair<Integer, Integer>, Integer>  getLimits() {
        return limits;
    }

    public Map<Pair<Integer, Integer>, Block> GetBlocks() {
        return blocks;
    }

    public Map<Pair<Integer, Integer>, Filter> GetFiltes() {
        return filters;
    }

    public Client getClient() {
        return client;
    }

    public Disruptor<Trace> getDisruptor() {
        return disruptor;
    }

}
