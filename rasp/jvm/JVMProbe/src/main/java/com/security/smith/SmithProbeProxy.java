package com.security.smith;
                           
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.regex.Pattern;
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
import com.security.smith.client.message.Trace;
import com.security.smith.client.message.Block;
import com.security.smith.common.Reflection;
import com.security.smith.common.SmithHandler;
import com.security.smith.log.SmithLogger;

public class SmithProbeProxy {
    private static final SmithProbeProxy ourInstance = new SmithProbeProxy();
    private static final int CLASS_MAX_ID = 30;
    private static final int METHOD_MAX_ID = 20;
    private static final int DEFAULT_QUOTA = 12000;
    
    private final AtomicIntegerArray[] quotas;
    private Disruptor<Trace> disruptor;
    private Client client;

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

    InheritableThreadLocal<Boolean> jettyDeploying = new InheritableThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return false;
        }
    };

    public SmithProbeProxy() {
         quotas = Stream.generate(() -> new AtomicIntegerArray(METHOD_MAX_ID)).limit(CLASS_MAX_ID).toArray(AtomicIntegerArray[]::new);
    }

    public static SmithProbeProxy getInstance() {
        return ourInstance;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public void setDisruptor(Disruptor<Trace> disruptor) {
        this.disruptor = disruptor;
    }

    public void detect(int classID, int methodID, Object[] args) {
        Map<Pair<Integer, Integer>, Block> blocks = SmithProbe.getInstance().GetBlocks();
        if (blocks == null)
            return;
        Block block = blocks.get(new ImmutablePair<>(classID, methodID));

        if (block == null)
            return;

        if (Arrays.stream(block.getRules()).filter(Objects::nonNull).anyMatch(rule -> {
            if (rule.getIndex() >= args.length)
                return false;
            if (args[rule.getIndex()] == null || rule.getRegex() == null)
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

            if (quota <= 0) {
                SmithProbe.getInstance().addDisacrdCount();
                return;
            }

            if (quotas[classID].compareAndSet(methodID, quota, quota - 1))
                break;
        }
        if (disruptor == null) {
            SmithProbe.getInstance().addDisacrdCount();
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

            ringBuffer.publish(sequence);
        } catch (InsufficientCapacityException ignored) {
            SmithProbe.getInstance().addDisacrdCount();
        }
    }

    public void sendMetadataObject(Object obj) {
        if (obj != null) {
            sendMetadataClass(obj.getClass());
        }
    }

    public void sendMetadataClass(Class<?> cla) {
        if (cla == null) {
            return;
        }

        if(SmithProbe.getInstance().classIsSended(cla)) {
            return ;
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

                    sendMetadataObject(clazz);
                } else {
                    needFoundfilterDef.set(filterdef);
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }
    public void checkFilterConfigPost(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
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

    public void checkWebSocketPre(int classID, int methodID, Object[] args) {
        SmithLogger.logger.info("check WebSocketPre");
        if (args.length < 2) {
            return;
        }
        try {
            Object ws = args[1];
            Class<?>[] emptyArgTypes = new Class[]{};
            Class<?> endpointCla = (Class<?>)Reflection.invokeMethod(ws, "getEndpointClass", emptyArgTypes);
            sendMetadataClass(endpointCla);

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
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
        } catch (Throwable e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check resin servlet
     */
    public void checkResinAddServletPre(int classID, int methodID, Object[] args)  {
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
        } catch (Throwable e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * check resin add filter memshell
     */
    public void checkResinAddFilterPre(int classID, int methodID, Object[] args) {
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
        } catch (Throwable e) {
            SmithLogger.exception(e);
        }

    }

    public void checkResinWebSocketPre(int classID, int methodID, Object[] args) {
        SmithLogger.logger.info("checkResinWebSocket pre_hook call success");
        if (args.length < 3) {
            return;
        }
        try {
            Object weblistener = args[2];
            if (weblistener != null) {
                sendMetadataObject(weblistener);
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
    public void checkJettyDeployPre(int classID, int methodID, Object[] args)  {
        if (jettyDeploying != null) {
            jettyDeploying.set(true);
        }
    }

    /* user for check ServerEndpointConfig init */
    public void checkWebSocketConfigPre(int classID, int metodID, Object[] args) {
        SmithLogger.logger.info("checkWebSocketConfigPre called");
        try {
            if (args.length < 2) {
                return;
            }
            Class<?>  websocket = (Class<?>)args[0];
            sendMetadataClass(websocket);

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    /*
     * used for listener check
     */
    public void checkJettyDeployPost(int classID, int methodID, Object[] args, Object ret, boolean blocked) {
        if (jettyDeploying != null) {
            jettyDeploying.set(false);
        }
    }

    /*
     * check spring controller memshell
     */
    public void checkSpringControllerPre(int classID, int methodID, Object[] args)  {
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

            if (((classname.startsWith("com.security.smith.") || 
                 classname.startsWith("com.security.smithloader.") ||
                 classname.startsWith("rasp.io")) ||
                 classname.startsWith("rasp.org") ||
                 classname.startsWith("rasp.com") ||
                 classname.startsWith("rasp.javassist")))
    
            return (Object)Class.forName(classname);
        }

        return null;
    }

    /*

    public ServletHandler addServlet(ServletInfo servletInfo) 
      
      
     */

     public void checkWildflyaddServletPre(int classID, int methodID, Object[] args) {
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
                        sendMetadataObject(servletClass);
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
                        sendMetadataObject(filterClass);
                    } else {
                        SmithLogger.logger.warning("can't find "+filterName);
                    }
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
     }

    /*
     *  used for glassfish org.apache.felix.framework.BundleWiringImpl$BundleClassLoader findClass loadClass hook
     */

    public  Object processGlassfishClassLoaderfindClassException(int classID, int methodID, Object[] args,Object exceptionObject) throws Throwable {
        //SmithLogger.logger.info("processGlassfishClassLoaderfindClass Exception_hook call success");
        if(exceptionObject instanceof ClassNotFoundException) {
            String classname = (String) args[1];
            //SmithLogger.logger.info("processGlassfishClassLoaderfindClass find class:"+classname);
            if (((classname.startsWith("com.security.smith.") || 
                 classname.startsWith("com.security.smithloader.") ||
                 classname.startsWith("rasp.io")) ||
                 classname.startsWith("rasp.org") ||
                 classname.startsWith("rasp.com") ||
                 classname.startsWith("rasp.javassist")))
    
            return (Object)Class.forName(classname);
        }

        return null;
    }
}

