package com.security.smith;
                           
import java.lang.reflect.Field;
import java.util.Arrays;
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
import com.security.smith.client.message.ClassFilter;
import com.security.smith.client.message.Heartbeat;
import com.security.smith.client.message.MatchRule;
import com.security.smith.client.message.Trace;
import com.security.smith.client.message.Block;
import com.security.smith.common.Reflection;
import com.security.smith.common.SmithHandler;
import com.security.smith.log.SmithLogger;

public class SmithProbeProxy {
    private static SmithProbeProxy ourInstance = new SmithProbeProxy();
    private static final int CLASS_MAX_ID = 30;
    private static final int METHOD_MAX_ID = 20;
    private static final int DEFAULT_QUOTA = 12000;
    
    private AtomicIntegerArray[] quotas;
    private Disruptor<Trace> disruptor;
    private Client client;
    private boolean stopX;

    public static InheritableThreadLocal<Object> localfilterConfig = new InheritableThreadLocal<Object>() {
        @Override
        protected Object initialValue() {
            return null;
        }
    };

    public static InheritableThreadLocal<Object> localfilterDef = new InheritableThreadLocal<Object>() {
        @Override
        protected Object initialValue() {
            return null;
        }
    };

    public static InheritableThreadLocal<Object> needFoundfilterDef = new InheritableThreadLocal<Object>() {
        @Override
        protected Object initialValue() {
            return null;
        }
    };

    public static InheritableThreadLocal<Boolean> jettyDeploying = new InheritableThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return false;
        }
    };

     private static  boolean removeThreadLocalFormThread(Object threadObj,Object threadLocalObj) {
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
                t.printStackTrace();
            }
        }

        return bret;
    }

    private static void RemoveThreadLocalVar() {
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

    class AtomicIntegerArraySupplier {
        public AtomicIntegerArray get() {
            return new AtomicIntegerArray(METHOD_MAX_ID);
        }
    }

    public SmithProbeProxy() {
        stopX = false;
        //quotas = Stream.generate(() -> new AtomicIntegerArray(METHOD_MAX_ID)).limit(CLASS_MAX_ID).toArray(AtomicIntegerArray[]::new);

        AtomicIntegerArraySupplier supplier = new AtomicIntegerArraySupplier();
        quotas = Stream.generate(supplier::get)
                                           .limit(CLASS_MAX_ID)
                                           .toArray(AtomicIntegerArray[]::new);
    }

    public static SmithProbeProxy getInstance() {
        return ourInstance;
    }

    public static void delInstance() {
        ourInstance.client = null;
        ourInstance.disruptor = null;
        for(int i = 0;i < ourInstance.quotas.length;i++) {
            ourInstance.quotas[i] = null;
        }
        ourInstance.quotas = null;
        RemoveThreadLocalVar();

        localfilterConfig = null; 
        localfilterDef = null;
        needFoundfilterDef = null;
        jettyDeploying = null;

        ourInstance = null;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public void setDisruptor(Disruptor<Trace> disruptor) {
        this.disruptor = disruptor;
    }

    public void detect(int classID, int methodID, Object[] args) {
        if(stopX) {
            return;
        }

        Map<Pair<Integer, Integer>, Block> blocks = SmithProbe.getInstance().GetBlocks();
        if (blocks == null)
            return;
        Block block = blocks.get(new ImmutablePair<>(classID, methodID));

        if (block == null)
            return;

            /* 
        if (Arrays.stream(block.getRules()).filter(Objects::nonNull).anyMatch(rule -> {
            if (rule.getIndex() >= args.length)
                return false;
            if (args[rule.getIndex()] == null || rule.getRegex() == null)
                return false;

            return Pattern.compile(rule.getRegex()).matcher(args[rule.getIndex()].toString()).find();
        })) {
            throw new SecurityException("API blocked by RASP");
        }
        */

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
        if (classID >= CLASS_MAX_ID || methodID >= METHOD_MAX_ID || stopX)
            return;

        while (true) {
            int quota = quotas[classID].get(methodID);

            if (quota <= 0)
                return;

            if (quotas[classID].compareAndSet(methodID, quota, quota - 1))
                break;
        }
        if (disruptor == null)
            return;
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

    public void sendMetadataObject(Object obj) {
        if(stopX) {
            return;
        }

        if (obj != null) {
            sendMetadataClass(obj.getClass());
        }
    }

    public void sendMetadataClass(Class<?> cla) {
        if (cla == null || stopX) {
            return;
        }
        ClassFilter classFilter = new ClassFilter();
        SmithHandler.queryClassFilter(cla, classFilter);
        classFilter.setTransId();
        classFilter.setRuleId(-1);
        classFilter.setStackTrace(Thread.currentThread().getStackTrace());
        if (client != null) {
            client.write(Operate.SCANCLASS, classFilter);
            SmithLogger.logger.info("send metadata: " + classFilter.toString());
            SmithProbe.getInstance().sendClass(cla, classFilter.getTransId());
        }
    }

    public void checkAddServletPre(int classID, int methodID, Object[] args) {
        if(stopX) {
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
                            sendMetadataObject(servlet);
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
        if(stopX) {
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
                    ClassFilter classFilter = new ClassFilter();
                    if (filterClass != null) {
                        SmithHandler.queryClassFilter(filterClass, classFilter);
                    } else {
                        SmithHandler.queryClassFilter(filter.getClass(), classFilter);
                    }
                    
                    classFilter.setTransId();
    
                    classFilter.setRuleId(-1);
                    classFilter.setStackTrace(Thread.currentThread().getStackTrace());
                    if (client != null) {
                        client.write(Operate.SCANCLASS, classFilter);
                        SmithLogger.logger.info("send metadata: " + classFilter.toString());
                        if (filterClass != null) {
                            SmithProbe.getInstance().sendClass(filterClass, classFilter.getTransId());
                        }
                        else {
                            SmithProbe.getInstance().sendClass(filter.getClass(), classFilter.getTransId());
                        }
                    }
                } else {
                    needFoundfilterDef.set(filterdef);
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }
    public void checkFilterConfigPost(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if(stopX) {
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
                sendMetadataObject(filter); 
            }
        } catch(Exception e) {
            SmithLogger.exception(e);
        }
    }

    public void checkAddValvePre(int classID, int methodID, Object[] args) {
        if(stopX) {
            return;
        }
        if (args.length < 2) {
            return;
        }
        try {
            Object valve = args[1];
            sendMetadataObject(valve);

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    public void checkAddListenerPre(int classID, int methodID, Object[] args) {
        checkAddValvePre(classID, methodID, args);
    }

    public  void onTimer() {
        Heartbeat heartbeat = SmithProbe.getInstance().getHeartbeat();
        if (client != null)
            client.write(Operate.HEARTBEAT, heartbeat);

        Map<Pair<Integer, Integer>, Integer> limits = SmithProbe.getInstance().getLimits();

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
        if(stopX) {
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
                sendMetadataClass(servletClass);
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check resin servlet
     */
    public void checkResinAddServletPre(int classID, int methodID, Object[] args)  {
        if(stopX) {
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
                sendMetadataClass(servletClass);
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check resin add filter memshell
     */
    public void checkResinAddFilterPre(int classID, int methodID, Object[] args) {
        if(stopX) {
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
                sendMetadataClass(filterCla);
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
        if(stopX) {
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
            sendMetadataClass(newclass);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check Jetty 9.4 Listener memshell
     */
    public void checkJettyListenerPre(int classID, int methodID, Object[] args) {
        if(stopX) {
            return;
        }
        SmithLogger.logger.info("checkJettyListenerPre pre_hook call success");
        if (args.length < 2) {
            return;
        }
        try {
            Object listener = args[1];
            sendMetadataObject(listener);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * used for listener check
     */
    public void cehckJettyDeployPre(int classID, int methodID, Object[] args)  {
        if(stopX) {
            return;
        }
        if (jettyDeploying != null) {
            jettyDeploying.set(true);
        }
    }

    /*
     * used for listener check
     */
    public void checkJettyDeployPost(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if(stopX) {
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
        if(stopX) {
            return;
        }
        if (args.length < 3) {
            return;
        }
        try {
            Object controller = args[2];
            sendMetadataObject(controller);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check spring Interceptor memshell
     */
    public void checkSpringInterceptorPre(int classID, int methodID, Object[] args)  {
        if(stopX) {
            return;
        }
        if (args.length < 1) {
            return;
        }
        try {
            Object interceptor = args[0];
            sendMetadataObject(interceptor);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    public void checkMemshellInitPost(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if(stopX) {
            return;
        }
        //SmithLogger.logger.info("checkMemshellInitPost call success");
        if (ret != null) {
            try {
                sendMetadataObject(ret);
            } catch (Exception e) {
                SmithLogger.exception(e);
            }
        }

    }

    /*
     *  used for wildfly ModuleClassLoader findClass hook
     */

    public  Object processWildflyClassLoaderException(int classID, int methodID, Object[] args,Object exceptionObject) throws Throwable {
        if(exceptionObject instanceof ClassNotFoundException) {
            String classname = (String) args[1];

            if (SmithProbeProxy.class.getClassLoader() == null && (classname.startsWith("com.security.smith.") || classname.startsWith("com.alibaba.third.rasp."))) {
                return (Object)Class.forName(classname);
            }
    
            throw (Throwable)exceptionObject;
        }

        return null;
    }

    /*

    public ServletHandler addServlet(ServletInfo servletInfo) 
      
      
     */

     public void checkWildflyaddServletPre(int classID, int methodID, Object[] args) {
        if(stopX) {
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
                        ClassFilter classFilter = new ClassFilter();
                        SmithHandler.queryClassFilter((Class<?>)servletClass, classFilter);
                        
                        classFilter.setTransId();
        
                        classFilter.setRuleId(-1);
                        classFilter.setStackTrace(Thread.currentThread().getStackTrace());
                        if (client != null) {
                            client.write(Operate.SCANCLASS, classFilter);
                            SmithLogger.logger.info("send metadata: " + classFilter.toString());
                            SmithProbe.getInstance().sendClass(servletClass, classFilter.getTransId());
                        }
                    } else {
                        SmithLogger.logger.warning("can't find "+servletName);
                    }
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
     }
}
