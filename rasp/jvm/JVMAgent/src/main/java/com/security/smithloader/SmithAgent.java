package com.security.smithloader;

import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import com.security.smithloader.MemCheck;
import com.security.smithloader.common.JarUtil;
import com.security.smithloader.common.ParseParameter;
import com.security.smithloader.common.Reflection;
import com.security.smithloader.log.SmithAgentLogger;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.concurrent.locks.ReentrantLock;

public class SmithAgent {
    private static ReentrantLock    xLoaderLock = new ReentrantLock();
    private static SmithLoader      xLoader = null;
    private static Class<?>         SmithProberClazz = null;
    private static Object           SmithProberObj = null;
    private static Object           SmithProberProxyObj = null;
    private static long             jvmHeapFree = 150;
    private static long             jvmMetaFree = 20;
    private static String probeVersion;
    private static String checksumStr;
    private static String proberPath;

    public static Object getClassLoader() {
        return xLoader;
    }

    public static Object getSmithProbeProxy() {
        return SmithProberProxyObj;
    }

    public static void PreProxy(Object MethodNameObj,int classID, int methodID, Object[] args) {

        if(SmithProberProxyObj != null) {
            String MethodName = (String)MethodNameObj;
            Class<?>[]  argType = new Class[]{int.class,int.class,Object[].class};
            Reflection.invokeMethod(SmithProberProxyObj,MethodName,argType,classID,methodID,args);
        }

    }

    public static void PostProxy(Object MethodNameObj,int classID, int methodID, Object[] args, Object ret, boolean blocked) {

        if(SmithProberProxyObj != null) {
            String MethodName = (String)MethodNameObj;
            Class<?>[]  argType = new Class[]{int.class,int.class,Object[].class,Object.class,boolean.class};
            Reflection.invokeMethod(SmithProberProxyObj,MethodName,argType,classID,methodID,args,ret,blocked);
        }
    }

    public static Object ExceptionProxy(Object MethodNameObj,int classID, int methodID, Object[] args,Object exceptionObject) throws Throwable {

        if(SmithProberProxyObj != null) {
            String MethodName = (String)MethodNameObj;
            Class<?>[]  argType = new Class[]{int.class,int.class,Object[].class,Object.class};
            return Reflection.invokeMethod(SmithProberProxyObj,MethodName,argType,classID,methodID,args,exceptionObject);
        }

        return null;
    }
  
    private static boolean loadSmithProber(String proberPath, Instrumentation inst) {
        boolean bret = false;
        boolean bexception = false;
        boolean binited = false;

        SmithAgentLogger.logger.info("loadSmithProber Entry");

        try {
            xLoader = new SmithLoader(proberPath, null);
            SmithProberClazz = xLoader.loadClass("com.security.smith.SmithProbe");
            
            Class<?>[] emptyArgTypes = new Class[]{};
            if (SmithProberClazz != null) {
                Constructor<?> constructor = SmithProberClazz.getDeclaredConstructor();
                constructor.setAccessible(true);
                SmithProberObj = constructor.newInstance();
                if (SmithProberObj != null) {
                    Class<?>[] objArgTypes = new Class[]{Object.class};
                    Reflection.invokeMethod(SmithProberObj,"setClassLoader",objArgTypes,xLoader);
                    Class<?>[]  argType = new Class[]{Instrumentation.class};
                    Reflection.invokeMethod(SmithProberObj,"setInst",argType,inst);
                    Reflection.invokeMethod(SmithProberObj,"init",emptyArgTypes);
                    SmithProberProxyObj = Reflection.invokeMethod(SmithProberObj,"getSmithProbeProxy", emptyArgTypes);
                    binited = true;


                    Reflection.invokeMethod(SmithProberObj,"start",emptyArgTypes);

                    bret = true; 
                } else {
                    SmithAgentLogger.logger.info("call SmithProbe init failed");
                } 
            } else {
                SmithAgentLogger.logger.info("load com.security.smith.SmithProbe failed");
                bret = false;
            }
            
        }
        catch(Exception e) {
            SmithAgentLogger.exception(e);
            bexception = true;
        }

        if(bexception) {
            if(binited) {
                try {
                    Class<?>[] emptyArgTypes = new Class[]{};
                    Reflection.invokeMethod(SmithProberObj,"stop",emptyArgTypes);
                    SmithProberProxyObj = null;
                    Reflection.invokeMethod(SmithProberObj,"uninit",emptyArgTypes);
                }
                catch(Exception e) {
                    SmithAgentLogger.exception(e);
                }
            }

            SmithProberObj = null;
            SmithProberClazz = null;
            xLoader = null;
        }

        SmithAgentLogger.logger.info("loadSmithProber Leave");

        return bret;
    }

    private static Boolean unLoadSmithProber() {
        boolean bret = false;

        SmithAgentLogger.logger.info("unLoadSmithProber Entry");

        try {
            if (SmithProberObj != null) {
                SmithAgentLogger.logger.info("Start unload prober");
                Class<?>[] emptyArgTypes = new Class[]{};
                Reflection.invokeMethod(SmithProberObj,"stop",emptyArgTypes);
                SmithProberProxyObj = null;
                SmithAgentLogger.logger.info("unload prober 0");
                Reflection.invokeMethod(SmithProberObj,"uninit",emptyArgTypes);
                SmithAgentLogger.logger.info("unload prober 1");

                SmithProberObj = null;
                SmithProberClazz = null;
                xLoader = null;

                SmithAgentLogger.logger.info("unload prober end");

                bret = true;
            } else {
                bret = true;
            }
        }
        catch(Exception e) {
            SmithAgentLogger.exception(e);
        }

        SmithAgentLogger.logger.info("unLoadSmithProber Leave");

        return bret;
    }

    private static String getProberVersion(String jarFilePath) {
        try {
            java.util.jar.JarFile jarFile = new java.util.jar.JarFile(jarFilePath);
            Manifest manifest = jarFile.getManifest();

            String ImplementationVersion = manifest.getMainAttributes().getValue("Implementation-Version");
            jarFile.close();

            return ImplementationVersion;
        }
        catch(Exception e) {
            SmithAgentLogger.exception(e);
        }

        return null;
    }

    public static void premain(String agentArgs, Instrumentation inst) {
        agentmain(agentArgs, inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        String agent = System.getProperty("rasp.probe");

        SmithAgentLogger.logger.info("agentArgs:"+agentArgs);

        StringBuilder cmd_sb = new StringBuilder();
        StringBuilder checksumStr_sb = new StringBuilder();
        StringBuilder proberPath_sb = new StringBuilder();
        String cmd = "";

        if(ParseParameter.parseParameter(agentArgs,cmd_sb,checksumStr_sb,proberPath_sb)) {
            cmd = cmd_sb.toString();
            SmithAgentLogger.logger.info("cmd:" + cmd);
            SmithAgentLogger.logger.info("parse parseParameter success");

            if(cmd.equals("attach")) {
                checksumStr = checksumStr_sb.toString();
                proberPath = proberPath_sb.toString();

                SmithAgentLogger.logger.info("checksumStr:" + checksumStr);
                SmithAgentLogger.logger.info("proberPath:" + proberPath); 

               /* 
                if(!JarUtil.checkJarFile(proberPath,checksumStr)) {
                    System.setProperty("smith.status", proberPath + " check fail");
                    SmithAgentLogger.logger.warning(proberPath + " check fail!");
                    return ;
                }
                */
                

                try {
                    inst.appendToBootstrapClassLoaderSearch(new JarFile(proberPath));
                }
                catch(Exception e) {
                    SmithAgentLogger.exception(e);
                }

                probeVersion = getProberVersion(proberPath);
                SmithAgentLogger.logger.info("proberVersion:" + probeVersion);

                xLoaderLock.lock();
                try {
                    if(xLoader != null) {
                        if(unLoadSmithProber()) {
                            System.setProperty("smith.status", "detach");
                        }
                        if (agent != null) {
                            System.clearProperty("rasp.probe");
                        }
                        xLoader = null;
                        SmithProberObj = null;
                        SmithProberClazz = null;
                    }
    
                    System.setProperty("smith.rasp", "");
                    if (!checkMemoryAvailable()) {
                        System.setProperty("smith.status",  "memory not enough");
                        SmithAgentLogger.logger.warning("checkMemory failed");
                    } else {
                        if(!loadSmithProber(proberPath,inst)) {
                            System.setProperty("smith.status",proberPath + " loading fail");
                            SmithAgentLogger.logger.warning(proberPath + " loading fail!");
                        }
                        else {
                            System.setProperty("smith.rasp", probeVersion+"-"+checksumStr);
                            System.setProperty("smith.status", "attach");
                            System.setProperty("rasp.probe", "smith");
                        }
                    }
                }
                finally {
                    xLoaderLock.unlock();
                }
            }
            else if(cmd.equals("detach")) {
                xLoaderLock.lock();
                try {
                    if(xLoader != null) {
                        if(unLoadSmithProber()) {
                            System.setProperty("smith.status", "detach");
                        }
                        else {
                            System.setProperty("smith.status", "prober unload fail");
                        }
                        xLoader = null;
                        SmithProberObj = null;
                        SmithProberClazz = null;
                        if (agent != null) {
                            System.clearProperty("rasp.probe");
                        }
                    }
                    else {
                        SmithAgentLogger.logger.warning("SmithProber No Loading!");
                    }
                }
                finally {
                    xLoaderLock.unlock();
                }
            } else {
                SmithAgentLogger.logger.warning("Unknow Command:"+cmd);
                return ;
            }
        }
        else {
            SmithAgentLogger.logger.info("parse parameter fail");
            return ;
        }

        

        if (agent != null) {
            SmithAgentLogger.logger.info("agent running");
            return;
        }
    }

    private static boolean checkMemoryAvailable() {
        try {
            long systemFree = MemCheck.getSystemMemoryFree();
            SmithAgentLogger.logger.info("systemmemory free: "+ systemFree);
            long cpuload = MemCheck.getSystemCpuLoad();
            SmithAgentLogger.logger.info("system cpu load: "+ cpuload);
            long heapFree = MemCheck.getHeapMemoryFree();
            if (heapFree < jvmHeapFree) {
                SmithAgentLogger.logger.info("heapmemory is not enough, free: "+ heapFree);
                return false;
            }
            else {
                SmithAgentLogger.logger.info("heapmemory is enough, free: "+ heapFree);
                long metaBeanFree = MemCheck.getMetaMemoryFree();
                if (metaBeanFree > 0L && metaBeanFree < jvmMetaFree) {
                    SmithAgentLogger.logger.info("metamemory is not enough, free: " + metaBeanFree);
                    return false;
                } else {
                    SmithAgentLogger.logger.info("metamemory is enough, free: " + metaBeanFree);
                }
            }
        
        } catch (Exception e) {
            SmithAgentLogger.exception(e);
        }
        return true;
        
    }
}
