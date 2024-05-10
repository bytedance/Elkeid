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
import java.util.regex.Matcher;
import java.util.stream.Collectors;

import java.io.FileOutputStream;
import java.io.IOException;

public class SmithProbe implements ClassFileTransformer, MessageHandler, EventHandler<Trace> {
    private static SmithProbe ourInstance = new SmithProbe();
    private static SmithProbeProxy smithProxy = null;
    private static int TRACE_BUFFER_SIZE = 1024;


    private Boolean disable;
    private Boolean scanswitch;
    private Instrumentation inst;
    private Client client;
    private Heartbeat heartbeat;
    
    private Map<String, SmithClass> smithClasses;
    private Map<String, Patcher> patchers;
    private Map<Pair<Integer, Integer>, Filter> filters;
    private Map<Pair<Integer, Integer>, Block> blocks;
    private Map<Pair<Integer, Integer>, Integer> limits;
    private Disruptor<Trace> disruptor;
    
    private Rule_Mgr    rulemgr;
    private Rule_Config ruleconfig;
    private Timer detectTimer;
    private Timer smithproxyTimer;
    private DetectTimerTask detectTimerTask;
    private SmithproxyTimerTask smithproxyTimerTask;

    enum Action {
        STOP,
        START
    }

    class DetectTimerTask extends TimerTask {
            boolean isCancel = false;

            @Override
            public void run() {
                if(!isCancel) {
                    onDetect();
                }
            }

            @Override
            public boolean cancel() {
                isCancel = true;
                return super.cancel();
            }
    }

    class SmithproxyTimerTask extends TimerTask {
            boolean isCancel = false;

            @Override
            public void run() {
                if(!isCancel) {
                    smithProxy.onTimer();
                }
            }

            @Override
            public boolean cancel() {
                isCancel = true;
                return super.cancel();
            }
    }

    public static SmithProbe getInstance() {
        return ourInstance;
    }

    public SmithProbe() {
        disable = false;
        scanswitch = true;
    }

    public void setInst(Instrumentation inst) {
        this.inst = inst;
    }

    public static Object getSmithProbeProxy() {
        return smithProxy;
    }

    public void init() {

        System.out.println("[init] Entry");
        smithClasses = new ConcurrentHashMap<>();
        patchers = new ConcurrentHashMap<>();
        filters = new ConcurrentHashMap<>();
        blocks = new ConcurrentHashMap<>();
        limits = new ConcurrentHashMap<>();

        heartbeat = new Heartbeat();

        client = new Client(this);
       
        disruptor = new Disruptor<>(Trace::new, TRACE_BUFFER_SIZE, DaemonThreadFactory.INSTANCE);
        rulemgr = new Rule_Mgr();
        ruleconfig = new Rule_Config(rulemgr);

        ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
        InputStream inputStream = this.getClass().getResourceAsStream("/class.yaml");

        if(inputStream != null) {
            System.out.println("finded class.yaml");
            try {
                for (SmithClass smithClass : objectMapper.readValue(inputStream, SmithClass[].class)) {
                    smithClasses.put(smithClass.getName(), smithClass);
                    System.out.println("hook point info:"+smithClass.getName());
                }
            } catch (IOException e) {
                SmithLogger.exception(e);
            }
        }
        else {
            System.out.println("not find class.yaml");
        }
        
        smithProxy = SmithProbeProxy.getInstance();
  
        System.out.println("[init] Leave");
    }

    public void start() {
        SmithLogger.logger.info("probe start");

        System.out.println("init ClassUploadTransformer");
        ClassUploadTransformer.getInstance().start(client, inst);

        inst.addTransformer(this, true);
        reloadClasses();

        Thread clientThread = new Thread(client::start);

        disruptor.handleEventsWith(this);
        disruptor.start();
    
        clientThread.setDaemon(true);
        clientThread.start();

        detectTimerTask = new DetectTimerTask();

        detectTimer = new Timer(true);
        detectTimer.schedule(
                detectTimerTask,
                TimeUnit.MINUTES.toMillis(1)
        );
        smithproxyTimerTask =  new SmithproxyTimerTask();

        smithproxyTimer = new Timer(true);
        smithproxyTimer.schedule(
                smithproxyTimerTask,
                0,
                TimeUnit.MINUTES.toMillis(1)
        );
        smithProxy.setClient(client);
        smithProxy.setDisruptor(disruptor);
    }

    public void stop() {
        SmithLogger.logger.info("probe stop");

        inst.removeTransformer(this);
        reloadClasses();
        SmithLogger.logger.info("probe stop 0");

        disable = true;
        scanswitch = false;

        ClassUploadTransformer.getInstance().stop();

        SmithLogger.logger.info("probe stop 1");

        detectTimer.cancel();
        smithproxyTimer.cancel();
        SmithLogger.logger.info("probe stop 2");
        
        disruptor.shutdown();
        SmithLogger.logger.info("probe stop 3");

        client.stop();
        SmithLogger.logger.info("probe stop 4");
        ruleconfig.destry();

        rulemgr.destry();
        SmithLogger.logger.info("probe stop 5");

        detectTimerTask = null;
        detectTimer =null;

        smithproxyTimerTask = null;
        smithproxyTimer = null;

        SmithLogger.logger.info("probe stop 7");
    }

    public void uninit() {
        SmithLogger.logger.info("probe uninit");
        ClassUploadTransformer.delInstance();
        
        smithProxy = null;
        SmithProbeProxy.delInstance();

        for (String key : smithClasses.keySet()) {
            SmithClass smithClass = smithClasses.get(key);
            smithClass.clear();
        }
        smithClasses.clear();
        smithClasses = null;
        patchers.clear();
        patchers = null;
        filters.clear();
        filters = null;
        blocks.clear();
        blocks = null;
        limits.clear();
        limits = null;
        SmithLogger.logger.info("probe uninit 0");
        
        disruptor = null;
        ruleconfig = null;
        rulemgr = null;
        client = null;

        heartbeat = null;
        inst = null;
        ourInstance = null;
        SmithLogger.logger.info("probe uninit 1");
    }

    private void reloadClasses() {
        reloadClasses(smithClasses.keySet());
    }

    private void reloadClasses(Collection<String> classes) {
        Class<?>[] loadedClasses = inst.getAllLoadedClasses();
        //Class<?>[] cls = Arrays.stream(loadedClasses).filter(c -> classes.contains(c.getName())).toArray(Class<?>[]::new);

        List<Class<?>> resultList = new ArrayList<>();
        for (Class<?> loadedClass : loadedClasses) {
            if (classes.contains(loadedClass.getName())) {
                resultList.add(loadedClass);
            }
        }
        Class<?>[] cls = resultList.toArray(new Class<?>[0]);

        SmithLogger.logger.info("reload: " + Arrays.toString(cls));
        //System.out.println("reload Class:"+cls.getClass().getName());

        try {
            inst.retransformClasses(cls);
        } catch (UnmodifiableClassException e) {
            SmithLogger.exception(e);
        }
    }

    public class MatchRulePredicate implements Predicate<MatchRule> {
        private final Trace trace;

         MatchRulePredicate(Trace trace) {
            this.trace = trace;
         }

        @Override
        public boolean test(MatchRule rule) {
            Object[] args = trace.getArgs();

            if (rule.getIndex() >= args.length || rule.getRegex().isEmpty() || args[rule.getIndex()] == null)
                return false;

            Pattern pattern = Pattern.compile(rule.getRegex());
            Matcher matcher = pattern.matcher(args[rule.getIndex()].toString());

            return matcher.find();
        }
    }

    @Override
    public void onEvent(Trace trace, long sequence, boolean endOfBatch) {
        Filter filter = filters.get(new ImmutablePair<>(trace.getClassID(), trace.getMethodID()));

        if (filter == null) {
            client.write(Operate.TRACE, trace);
            return;
        }

        Predicate<MatchRule> pred = new MatchRulePredicate(trace);

        /* 
        Predicate<MatchRule> pred = rule -> {
            Object[] args = trace.getArgs();

            if (rule.getIndex() >= args.length || rule.getRegex().isEmpty() || args[rule.getIndex()] == null)
                return false;

            return Pattern.compile(rule.getRegex()).matcher(args[rule.getIndex()].toString()).find();
        };
        */

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

    public boolean checkInterfaceNeedTran(String interfaceName) {
        if (interfaceName == null) {
            return false;
        }
        boolean ret = false;
        switch (interfaceName) {
            case "org/springframework/web/servlet/HandlerInterceptor":
            case "javax/servlet/Servlet":
            case "javax/servlet/Filter":
            case "javax/servlet/ServletRequestListener":
            case "jakarta/servlet/Servlet":
            case "jakarta/servlet/Filter":
            case "jakarta/servlet/ServletRequestListener":
            case "javax/websocket/Endpoint":
                ret = true;
                break;
            default:
                break;
        }
        return ret;
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
     
        if (smithClass == null && className == null)  {
            
            ClassReader cr = new ClassReader(classfileBuffer);
            String[] interfaces = cr.getInterfaces();
            if (className == null) {
                className = cr.getClassName();
                classType = Type.getObjectType(className);
            }

            for (String interName : interfaces) {
                if (checkInterfaceNeedTran(interName)) {
                    Type interfaceType = Type.getObjectType(interName);
                    smithClass = smithClasses.get(interfaceType.getClassName());
                    break;
                }
            }
            if (smithClass == null) {
                return null;
            }
        } 

        if (smithClass == null) {
            return null;
        }

        try {
            //Map<String, SmithMethod> methodMap = smithClass.getMethods().stream().collect(Collectors.toMap(method -> method.getName() + method.getDesc(), method -> method));
            Map<String, SmithMethod> methodMap = new HashMap<>();
            List<SmithMethod> methods = smithClass.getMethods();

            for (SmithMethod method : methods) {
                String key = method.getName() + method.getDesc();
                methodMap.put(key, method);
            }
                        
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
            /* 
            try (FileOutputStream fos = new FileOutputStream("/tmp/"+classType.getClassName()+".class")) {
                byte[] bytecode = classWriter.toByteArray();
                fos.write(bytecode);
                System.out.println(classType.getClassName() + " 字节码保存成功！");
            } catch (IOException e) {
                e.printStackTrace();
            }
            */

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

        /* 
        patchers.keySet().stream().filter(name -> !active.contains(name)).forEach(
                name -> {
                    SmithLogger.logger.info("uninstall patch: " + name);

                    Patcher patcher = patchers.remove(name);

                    if (patcher == null)
                        return;

                    patcher.uninstall();
                }
        );
        */

        for (String name : patchers.keySet()) {
            if (!active.contains(name)) {
                SmithLogger.logger.info("uninstall patch: " + name);
                Patcher patcher = patchers.remove(name);
                if (patcher == null)
                    continue;
                patcher.uninstall();
            }
        }

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

    public Heartbeat getHeartbeat() {
        return heartbeat;
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
