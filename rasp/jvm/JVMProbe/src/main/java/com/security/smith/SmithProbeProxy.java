package com.security.smith;
                           
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.stream.Stream;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import com.lmax.disruptor.InsufficientCapacityException;
import com.lmax.disruptor.RingBuffer;
import com.lmax.disruptor.dsl.Disruptor;
import com.security.smith.client.Client;
import com.security.smith.client.Operate;
import com.security.smith.client.message.*;
import com.security.smith.common.Reflection;
import com.security.smith.common.SmithHandler;
import com.security.smith.log.SmithLogger;
import com.security.smith.ruleengine.JsRuleResult;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.GsonBuilder;
public class SmithProbeProxy {
    private final int CLASS_MAX_ID = 50;
    private final int METHOD_MAX_ID = 20;
    private final int DEFAULT_QUOTA = 12000;
    
    private SmithProbe SmithProbeObj = null;
    private AtomicIntegerArray[] quotas;
    private Disruptor<Trace> disruptor;
    private Client client;
    private boolean stopX;

    public InheritableThreadLocal<Object> localfilterConfig = new InheritableThreadLocal<Object>() {
        @Override
        protected Object initialValue() {
            return null;
        }
    };

    public InheritableThreadLocal<Object> localfilterDef = new InheritableThreadLocal<Object>() {
        @Override
        protected Object initialValue() {
            return null;
        }
    };

    public InheritableThreadLocal<Object> needFoundfilterDef = new InheritableThreadLocal<Object>() {
        @Override
        protected Object initialValue() {
            return null;
        }
    };

    public InheritableThreadLocal<Boolean> jettyDeploying = new InheritableThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return false;
        }
    };

     private boolean removeThreadLocalFormThread(Object threadObj,Object threadLocalObj) {
        boolean bret = false;
        boolean usegetMap = false;

        if(threadObj == null ||
           threadLocalObj == null)  {
            return false;
        }

        try {
            String className = threadLocalObj.getClass().getSuperclass().getName();
            if(className.contains("java.lang.InheritableThreadLocal")) {
                Class<?>[]  argType_remove = new Class[]{Thread.class};
                 bret = Reflection.invokeSuperSuperMethodNoReturn(threadLocalObj,"remove",argType_remove,threadObj);
            }
            else if(className.contains("java.lang.ThreadLocal")) {
                Class<?>[]  argType_remove = new Class[]{Thread.class};
                bret = Reflection.invokeSuperMethodNoReturn(threadLocalObj,"remove",argType_remove,threadObj);
            }
        }
        catch(Throwable t) {
        }

        if(!bret) {
            try {
                Class<?>[]  argType_getMap = new Class[]{Thread.class};
                Object threadlocalMap = Reflection.invokeSuperMethod(threadLocalObj,"getMap",argType_getMap,threadObj);
                if(threadlocalMap != null) {
                    Class<?>[]  argType_remove = new Class[]{ThreadLocal.class};
                    bret = Reflection.invokeMethodNoReturn(threadlocalMap,"remove",argType_remove,threadLocalObj);

                }
            }
            catch(Throwable t) {
                SmithLogger.exception(t);
            }
        }

        return bret;
    }

    private void RemoveThreadLocalVar() {
        int activeCount = Thread.activeCount();
        Thread[] threads = new Thread[activeCount+100];
        int count = Thread.enumerate(threads);
        for (int i = 0; i < count; i++) {
            removeThreadLocalFormThread(threads[i], localfilterConfig);
            removeThreadLocalFormThread(threads[i], localfilterDef);
            removeThreadLocalFormThread(threads[i], needFoundfilterDef);
            removeThreadLocalFormThread(threads[i], jettyDeploying);
        }
    }

    public SmithProbeProxy() {
        stopX = false;

        quotas = new AtomicIntegerArray[CLASS_MAX_ID];
        for (int i = 0; i < CLASS_MAX_ID; i++) {
            quotas[i] = new AtomicIntegerArray(METHOD_MAX_ID);
        }
    }

     public void uninit() {
        this.client = null;
        this.disruptor = null;
        for(int i = 0;i < this.quotas.length;i++) {
            this.quotas[i] = null;
        }
        this.quotas = null;
        this.SmithProbeObj = null;
        RemoveThreadLocalVar();

        localfilterConfig = null; 
        localfilterDef = null;
        needFoundfilterDef = null;
        jettyDeploying = null;
    }

    public void setProbe(SmithProbe SmithProbeObj) {
        this.SmithProbeObj = SmithProbeObj;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public void setDisruptor(Disruptor<Trace> disruptor) {
        this.disruptor = disruptor;
    }


    public boolean checkReflectEvil(String classname, String fieldname, boolean isMethod) {
        if (classname == null || fieldname == null) {
            return false;
        }
        try {
            Object[] argsX = new Object[3];
            argsX[0] = (Object)classname;
            argsX[1] = (Object)fieldname;
            argsX[2] = (Object)isMethod;

            JsRuleResult result = SmithProbeObj.getJsRuleEngine().detect(2, argsX);
            if (result != null) {
                SmithLogger.logger.info("classname = " + classname + ", fieldname = " + fieldname + ", result = " + result.rulename);
                SmithLogger.logger.info("classname = " + classname + ", fieldname = " + fieldname + ", result = " + result.ruleid);
                return true;
            }
        } catch (Throwable e) {
            SmithLogger.exception(e);
        }
        
        return false;
    }

    public void detect(int classID, int methodID, Object[] args) {
        if(stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }

        Map<Pair<Integer, Integer>, Block> blocks = SmithProbeObj.GetBlocks();
        if (blocks == null)
            return;
        Block block = blocks.get(new ImmutablePair<>(classID, methodID));

        if (block == null)
            return;

        MatchRule[] rules = block.getRules();
        boolean isBlocked = false;

        for (MatchRule rule : rules) {
            if (rule != null) {
                if (rule.getIndex() >= args.length || args[rule.getIndex()] == null || rule.getRegex() == null) {
                    continue;
                }

                Pattern pattern = Pattern.compile(rule.getRegex());
                Matcher matcher = pattern.matcher(args[rule.getIndex()].toString());

                if (matcher.find()) {
                    isBlocked = true;
                    break;
                }
            }
        }

        if (isBlocked) {
            throw new SecurityException("API blocked by RASP");
        }
    }

    public void trace(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if (classID >= CLASS_MAX_ID || methodID >= METHOD_MAX_ID || stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false)
            return;

        while (true) {
            int quota = quotas[classID].get(methodID);

            if (quota <= 0) {
                SmithProbeObj.addDisacrdCount();
                return;
            }

            if (quotas[classID].compareAndSet(methodID, quota, quota - 1))
                break;
        }
        if (disruptor == null) {
            SmithProbeObj.addDisacrdCount();
            return;
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
            trace.setTypes(SmithProbeObj.getFuncTypes(classID, methodID));

            ringBuffer.publish(sequence);
        } catch (InsufficientCapacityException ignored) {
            SmithProbeObj.addDisacrdCount();
        }
    }

    public void sendMetadataObject(Object obj, int classID, int methodID) {
        if(stopX) {
            return;
        }

        if (obj != null) {
            sendMetadataClass(obj.getClass(), classID, methodID);
        }
    }

    public void sendMetadataClass(Class<?> cla, int classID, int methodID) {
        if (cla == null || stopX) {
            return;
        }

        if(SmithProbeObj.classIsSended(cla)) {
            return ;
        }
        
        Object[] argsX = new Object[2];
        argsX[0] = (Object)classID;
        argsX[1] = (Object)methodID;

        JsRuleResult result = SmithProbeObj.getJsRuleEngine().detect(1,argsX);
        if(result != null) {
            SmithLogger.logger.info("Js Rule Result +" + result.toString());
            ClassFilter classFilter = new ClassFilter();
            SmithHandler.queryClassFilter(cla, classFilter);
            classFilter.setTransId();
            classFilter.setRuleId(-1);
            classFilter.setClassId(classID);
            classFilter.setMethodId(methodID);
            classFilter.setTypes(SmithProbeObj.getFuncTypes(classID, methodID));
            classFilter.setStackTrace(Thread.currentThread().getStackTrace());
            if (client != null) {
                Gson gson = new GsonBuilder()
                .registerTypeAdapter(ClassFilter.class, new ClassFilterSerializer())
                .registerTypeAdapter(ClassFilter.class, new ClassFilterDeserializer())
                .create();
                JsonElement jsonElement = gson.toJsonTree(classFilter);
                client.write(Operate.SCANCLASS, jsonElement);
                SmithLogger.logger.info("send metadata: " + classFilter.toString());
                SmithProbeObj.sendClass(cla, classFilter.getTransId());
            }
        }
        else {
            SmithLogger.logger.info("Js Rule No hit");
        }
        
    }

    public void checkAddServletPre(int classID, int methodID, Object[] args) {
        if(stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkAddServlet pre_hook call success");

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
                            sendMetadataObject(servlet, classID, methodID);
                        }
            }

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    private Object getFilterFromConfig(Object filterConfig) {
        if (filterConfig == null) {
            return null;
        }
        Object filter = null;
        try {
            filter = Reflection.getField(filterConfig, "filter");
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        return filter;
    }

    private Class<?> getFilterFromLoader(Object context, String filterName) {
        Class<?> filter = null;
        if (context == null || filterName == null)
            return filter;
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null)
          classLoader = context.getClass().getClassLoader();
        try {
          filter = classLoader.loadClass(filterName);
        } catch (Exception e) {
        } 
        return filter;
    }

    public void checkAddFilterPre(int classID, int methodID, Object[] args) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkAddFilter pre_hook call success");
        if (args.length < 2) {
            return;
        }
        try {
            
            Object filterdef = args[1];
            Object filter = null;
            Class<?> filterClass = null;
            if (filterdef != null) {
                Class<?>[] emptyArgTypes = new Class[]{};
                filter = Reflection.invokeMethod(filterdef, "getFilter", emptyArgTypes);
                String filterName = "";
                if (filter == null) {
                    // Godzilla filter check
                    if (localfilterDef != null && localfilterConfig != null && filterdef == localfilterDef.get()) {
                        filter = getFilterFromConfig(localfilterConfig.get());
                    } else {
                        filterName = (String)Reflection.invokeMethod(filterdef, "getFilterClass", emptyArgTypes);
                        filterClass = getFilterFromLoader(args[0], filterName);
                    }
                }
                if (filter != null || filterClass != null) {
                    Class<?> clazz = null;
                    if (filterClass != null) {
                        clazz = filterClass;
                    } else {
                        clazz = filter.getClass();
                    }

                    sendMetadataObject(clazz, classID, methodID);
                } else {
                    needFoundfilterDef.set(filterdef);
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }
    public void checkFilterConfigPost(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkAddFilter post_hook call success");
        if (ret == null || args.length < 2) {
            return;
        }
        try {
            localfilterConfig.set(ret);
            localfilterDef.set(args[1]);

            // shiro filter check
            if (needFoundfilterDef != null && needFoundfilterDef.get() == args[1]) {
                Object filter = getFilterFromConfig(ret);
                sendMetadataObject(filter, classID, methodID); 
            }
        } catch(Exception e) {
            SmithLogger.exception(e);
        }
    }

    public void checkAddValvePre(int classID, int methodID, Object[] args) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        if (args.length < 2) {
            return;
        }
        try {
            Object valve = args[1];
            sendMetadataObject(valve, classID, methodID);

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    public void checkAddListenerPre(int classID, int methodID, Object[] args) {
        checkAddValvePre(classID, methodID, args);
    }

    public void checkWebSocketPre(int classID, int methodID, Object[] args) {
        if  (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("check WebSocketPre");
        if (args.length < 2) {
            return;
        }
        try {
            Object ws = args[1];
            Class<?>[] emptyArgTypes = new Class[]{};
            Class<?> endpointCla = (Class<?>)Reflection.invokeMethod(ws, "getEndpointClass", emptyArgTypes);
            sendMetadataClass(endpointCla, classID, methodID);

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    public  void onTimer() {
        Heartbeat heartbeat = SmithProbeObj.getHeartbeat();
        if (client != null)
            client.write(Operate.HEARTBEAT, heartbeat.toJsonElement());

        Map<Pair<Integer, Integer>, Integer> limits = SmithProbeObj.getLimits();

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

    public void checkResinAddServletPost(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        if (args.length < 2) {
            return;
        }
        try {
            Object servletMapping = args[1];
            if (servletMapping != null) { 
                Class<?>[] emptyArgTypes = new Class[]{};
                Class<?> servletClass = (Class<?>)Reflection.invokeMethod(servletMapping, "getServletClass", emptyArgTypes);
                sendMetadataClass(servletClass, classID, methodID);
            }
        } catch (Throwable e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check resin servlet
     */
    public void checkResinAddServletPre(int classID, int methodID, Object[] args)  {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        if (args.length < 2) {
            return;
        }
        try {
            Object servletMapping = args[1];
            if (servletMapping != null) { 
                Class<?>[] emptyArgTypes = new Class[]{};
                Class<?> servletClass = (Class<?>)Reflection.invokeMethod(servletMapping, "getServletClass", emptyArgTypes);
                sendMetadataClass(servletClass, classID, methodID);
            }
        } catch (Throwable e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check resin add filter memshell
     */
    public void checkResinAddFilterPre(int classID, int methodID, Object[] args) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkResinAddFilter pre_hook call success");
        if (args.length < 2) {
            return;
        }
        try {
            Object filterdef = args[1];
            if (filterdef != null) {
                Class<?>[] emptyArgTypes = new Class[]{};
                Class <?> filterCla = (Class<?>)Reflection.invokeMethod(filterdef, "getFilterClass", emptyArgTypes);
                sendMetadataClass(filterCla, classID, methodID);
            }
        } catch (Throwable e) {
            SmithLogger.exception(e);
        }

    }

    public void checkResinWebSocketPre(int classID, int methodID, Object[] args) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkResinWebSocket pre_hook call success");
        if (args.length < 3) {
            return;
        }
        try {
            Object weblistener = args[2];
            if (weblistener != null) {
                sendMetadataObject(weblistener, classID, methodID);
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }
     /*
     * check jetty version 9 add filter/servlet memshell
     * TODO: add url check
     */
    public void checkJettyMemshellPre(int classID, int methodID, Object[] args) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkJettyMemshellPre pre_hook call success");
        if (jettyDeploying != null && jettyDeploying.get() == true) {
            return;
        }
        if (args.length < 2) {
            return;
        }
        try {
            Class<?> newclass = (Class<?>)args[1];
            sendMetadataClass(newclass, classID, methodID);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check Jetty 9.4 Listener memshell
     */
    public void checkJettyListenerPre(int classID, int methodID, Object[] args) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkJettyListenerPre pre_hook call success");
        if (args.length < 2) {
            return;
        }
        try {
            Object listener = args[1];
            sendMetadataObject(listener, classID, methodID);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * used for listener check
     */
    public void cehckJettyDeployPre(int classID, int methodID, Object[] args)  {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        if (jettyDeploying != null) {
            jettyDeploying.set(true);
        }
    }

    /* user for check ServerEndpointConfig init */
    public void checkWebSocketConfigPre(int classID, int metodID, Object[] args) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, metodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkWebSocketConfigPre called");
        try {
            if (args.length < 2) {
                return;
            }
            Class<?>  websocket = (Class<?>)args[0];
            sendMetadataClass(websocket, classID, metodID);

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * used for listener check
     */
    public void checkJettyDeployPost(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if  (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        if (jettyDeploying != null) {
            jettyDeploying.set(false);
        }
    }

    /*
     * check spring controller memshell
     */
    public void checkSpringControllerPre(int classID, int methodID, Object[] args)  {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        if (args.length < 3) {
            return;
        }
        try {
            Object controller = args[2];
            sendMetadataObject(controller, classID, methodID);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check spring Interceptor memshell
     */
    public void checkSpringInterceptorPre(int classID, int methodID, Object[] args)  {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        if (args.length < 1) {
            return;
        }
        try {
            Object interceptor = args[0];
            sendMetadataObject(interceptor, classID, methodID);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    public void checkMemshellInitPost(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        //SmithLogger.logger.info("checkMemshellInitPost call success");
        if (ret != null) {
            try {
                sendMetadataObject(ret, classID, methodID);
            } catch (Exception e) {
                SmithLogger.exception(e);
            }
        }

    }

    private boolean checkIsRaspClass(String classname) {

        if (((classname.startsWith("com.security.smith.") || 
                classname.startsWith("com.security.smithloader.") ||
                classname.startsWith("rasp.io")) ||
                classname.startsWith("rasp.org") ||
                classname.startsWith("rasp.com") ||
                classname.startsWith("rasp.javassist"))) {
            return true;
        }

        return false;
    }

    /*
     *  used for wildfly ModuleClassLoader findClass hook
     */

    public  Object processWildflyClassLoaderException(int classID, int methodID, Object[] args,Object exceptionObject) throws Throwable {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return null;
        }
        if(exceptionObject instanceof ClassNotFoundException) {
            String classname = (String) args[1];

            if(checkIsRaspClass(classname)) {
                return (Object)Class.forName(classname);
            }
        }

        return null;
    }

    /*

    public ServletHandler addServlet(ServletInfo servletInfo) 
      
      
     */

     public void checkWildflyaddServletPre(int classID, int methodID, Object[] args) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkWildflyaddServlet pre_hook call success");
        if(args.length < 2) {
            return ;
        }

        try {
            Object servletInfo = args[1];
            if(servletInfo != null) {
                Class<?> servletClass = (Class<?>)Reflection.getField(servletInfo,"servletClass");
                String servletName = (String)Reflection.getField(servletInfo,"name");

                if(servletName != null) {
                    if (servletClass != null) {
                        sendMetadataObject(servletClass, classID, methodID);
                    } else {
                        SmithLogger.logger.warning("can't find "+servletName);
                    }
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
     }

         /*

    public ManagedFilter addFilter(FilterInfo filterInfo)
      
      
     */

     public void checkWildflyaddFilterPre(int classID, int methodID, Object[] args) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        SmithLogger.logger.info("checkWildflyaddFilter pre_hook call success");
        if(args.length < 2) {
            return ;
        }

        try {
            Object filterInfo = args[1];
            if(filterInfo != null) {
                Class<?> filterClass = (Class<?>)Reflection.getField(filterInfo,"filterClass");
                String filterName = (String)Reflection.getField(filterInfo,"name");

                if(filterName != null) {
                    if (filterClass != null) {
                        sendMetadataObject(filterClass, classID, methodID);
                    } else {
                        SmithLogger.logger.warning("can't find "+filterName);
                    }
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
     }

     public void handleReflectField(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if(stopX) {
            return;
        }
        if (args.length < 2) {
            return ;
        }
        try {
            Class<?> clas = (Class<?>)args[0];
            String reflectClass = clas.getName();
            String feild = (String)args[1];
            if (reflectClass.startsWith("com.security.smith") || reflectClass.startsWith("rasp.")) {
                return ;
            } else {
                if (checkReflectEvil(reflectClass, feild, false)) {
                    trace(classID, methodID, args, ret, blocked);
                }
            }
        } catch (Throwable e) {
            SmithLogger.exception(e);
        }
    }
    
    public void handleReflectMethod(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return;
        }
        if (args.length < 2) {
            return ;
        }
        try {
            Class<?> clas = (Class<?>)args[0];
            String reflectClass = clas.getName();
            String feild = (String)args[1];
            if (reflectClass.startsWith("com.security.smith") || reflectClass.startsWith("rasp.")) {
                return ;
            } else {
                if (checkReflectEvil(reflectClass, feild, true)) {
                    trace(classID, methodID, args, ret, blocked);
                }
            }
        } catch (Throwable e) {
            SmithLogger.exception(e);
        }
    }

    /*
     *  used for glassfish org.apache.felix.framework.BundleWiringImpl$BundleClassLoader findClass loadClass hook
     */

    public  Object processGlassfishClassLoaderfindClassException(int classID, int methodID, Object[] args,Object exceptionObject) throws Throwable {
        //SmithLogger.logger.info("processGlassfishClassLoaderfindClass Exception_hook call success");
        if (stopX || SmithProbeObj.isFunctionEnabled(classID, methodID) == false) {
            return null;
        }
        if(exceptionObject instanceof ClassNotFoundException) {
            String classname = (String) args[1];
            //SmithLogger.logger.info("processGlassfishClassLoaderfindClass find class:"+classname);
            if(checkIsRaspClass(classname)) {
                return (Object)Class.forName(classname);
            }
        }

        return null;
    }
}

