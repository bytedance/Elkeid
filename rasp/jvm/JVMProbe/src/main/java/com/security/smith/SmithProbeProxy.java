package com.security.smith;

import java.util.Arrays;
import java.util.Map;
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
                            if(servlet != null) {
                                ClassFilter classFilter = new ClassFilter();
                                //classFilter.setClassName(name);
                                SmithHandler.queryClassFilter(servlet.getClass(), classFilter);
                                classFilter.setTransId();
                                classFilter.setRuleId(-1);
                                classFilter.setStackTrace(Thread.currentThread().getStackTrace());
                                if (client != null) {
                                    client.write(Operate.SCANCLASS, classFilter);
                                    SmithLogger.logger.info("send metadata: " + classFilter.toString());
                                    SmithProbe.getInstance().sendClass(servlet.getClass(), classFilter.getTransId());
                                }
                            }
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
                if (filter != null) {
                    ClassFilter classFilter = new ClassFilter();
                        SmithHandler.queryClassFilter(filter.getClass(), classFilter);
                    
                        classFilter.setTransId();
        
                        classFilter.setRuleId(-1);
                        classFilter.setStackTrace(Thread.currentThread().getStackTrace());
                        if (client != null) {
                            client.write(Operate.SCANCLASS, classFilter);
                            SmithLogger.logger.info("send metadata: " + classFilter.toString());
                            
                            SmithProbe.getInstance().sendClass(filter.getClass(), classFilter.getTransId());
                        }
                }  
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
            if (valve != null) {
                ClassFilter classFilter = new ClassFilter();
                SmithHandler.queryClassFilter(valve.getClass(), classFilter);
                classFilter.setTransId();
                classFilter.setRuleId(-1);
                classFilter.setStackTrace(Thread.currentThread().getStackTrace());
                if (client != null) {
                    client.write(Operate.SCANCLASS, classFilter);
                    SmithLogger.logger.info("send metadata: " + classFilter.toString());
                    SmithProbe.getInstance().sendClass(valve.getClass(), classFilter.getTransId());
                }
            }

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

}
