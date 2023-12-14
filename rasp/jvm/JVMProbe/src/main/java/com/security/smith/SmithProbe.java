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
import com.security.smith.client.message.*;
import com.security.smith.common.Reflection;
import com.security.smith.common.SmithHandler;
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
    private Boolean scanswitch;
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
    private final Rule_Mgr    rulemgr;
    private final Rule_Config ruleconfig;

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

        heartbeat = new Heartbeat();
        client = new Client(this);
        disruptor = new Disruptor<>(Trace::new, TRACE_BUFFER_SIZE, DaemonThreadFactory.INSTANCE);
        quotas = Stream.generate(() -> new AtomicIntegerArray(METHOD_MAX_ID)).limit(CLASS_MAX_ID).toArray(AtomicIntegerArray[]::new);

        rulemgr = new Rule_Mgr();
        ruleconfig = new Rule_Config(rulemgr);
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

    public void checkAddServletPre(int classID, int methodID, Object[] args) {
        SmithLogger.logger.info("checkAddServlet post_hook call success");
        if (args.length < 3) {
            return;
        }
        try {
            Object context = args[0];
            String name = (String)args[2];
            if (context != null) {
                 Class<?>[] argTypes = new Class[]{String.class};

                        Object wrapper = Reflection.invokeMethod(context, "findChild", argTypes, name);

                        if(wrapper != null) {
                            Class<?>[] emptyArgTypes = new Class[]{};

                            Object servlet = Reflection.invokeMethod(wrapper, "getServlet", emptyArgTypes);
                            if(servlet != null) {
                                ClassFilter classFilter = new ClassFilter();
                                //classFilter.setClassName(name);
                                SmithHandler.queryClassFilter(servlet.getClass(), classFilter);
                                classFilter.setTransId();
                                classFilter.setRuleId(-1);
                                classFilter.setStackTrace(Thread.currentThread().getStackTrace());
                                client.write(Operate.SCANCLASS, classFilter);
                                SmithLogger.logger.info("send metadata: " + classFilter.toString());
                                sendClass(servlet.getClass(), classFilter.getTransId());
                            }
                        }
            }

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

     public void checkAddFilterPre(int classID, int methodID, Object[] args) {
        SmithLogger.logger.info("checkAddFilter post_hook call success");
        if (args.length < 2) {
            return;
        }
        try {
            Object filterDef = args[1];
            Object filter = null;
            if (filterDef != null) {
                Class<?>[] emptyArgTypes = new Class[]{};
                filter = Reflection.invokeMethod(filterDef, "getFilter", emptyArgTypes);
                if (filter != null) {
                    ClassFilter classFilter = new ClassFilter();
                    SmithHandler.queryClassFilter(filter.getClass(), classFilter);
                    classFilter.setTransId();
                    classFilter.setRuleId(-1);
                    classFilter.setStackTrace(Thread.currentThread().getStackTrace());
                    client.write(Operate.SCANCLASS, classFilter);
                    SmithLogger.logger.info("send metadata: " + classFilter.toString());
                    sendClass(filter.getClass(), classFilter.getTransId());
                }
                
            }
    
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
     }

     public void checkAddValvePre(int classID, int methodID, Object[] args) {
        if (args.length < 2) {
            return;
        }
        try {
            Object valve = args[1];
            if (valve != null) {
                ClassFilter classFilter = new ClassFilter();
                SmithHandler.queryClassFilter(valve.getClass(), classFilter);
                classFilter.setTransId();
                classFilter.setRuleId(-1);
                classFilter.setStackTrace(Thread.currentThread().getStackTrace());
                client.write(Operate.SCANCLASS, classFilter);
                SmithLogger.logger.info("send metadata: " + classFilter.toString());
                sendClass(valve.getClass(), classFilter.getTransId());
            }

        } catch (Exception e) {
           SmithLogger.exception(e);
        }
     }

     public void checkAddListenerPre(int classID, int methodID, Object[] args) {
        checkAddValvePre(classID, methodID, args);
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
                // 获取父类名和父类加载器
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

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
         if (disable)
            return null;

        if(scanswitch) {
            checkClassFilter(loader, className,classfileBuffer);
        }
  
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

    
    /* 全量扫描 */
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
    private void sendClass(Class<?> clazz, String transId) {
        if (clazz == null || transId == null) {
            return;
        }
        try {
            ClassUploadTransformer transformer = new ClassUploadTransformer(clazz, client, transId);
            try {
                inst.addTransformer(transformer, true);
                if (inst.isModifiableClass(clazz) && !clazz.getName().startsWith("java.lang.invoke.LambdaForm")) {
                    try {
                        inst.retransformClasses(clazz);
                    } catch (Exception e) {
                        SmithLogger.exception(e);
                    }
                }
            } finally {
                if (transformer != null) {
                    inst.removeTransformer(transformer);
                }
            }
         
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
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
        // TODO 第一版先不分包，看下性能
        // client.write(Operate.CLASSDUMP, classUpload);
        // 发送文件内容分包给服务器
        // int packetSize = 1024; // 每个包的大小
        // int totalPackets = (data.length + packetSize - 1) / packetSize; // 总包数
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

}
