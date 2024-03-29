package com.security.smith.client;

import java.lang.instrument.Instrumentation;
import java.lang.instrument.ClassFileTransformer;
import java.lang.Class;

import java.security.ProtectionDomain;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import com.security.smith.client.message.ClassFilter;
import com.security.smith.client.message.ClassUpload;
import com.security.smith.common.ProcessHelper;
import com.security.smith.log.SmithLogger;

import io.netty.buffer.Unpooled;

import java.lang.instrument.IllegalClassFormatException;
import java.lang.management.ManagementFactory;

public class ClassUploadTransformer implements ClassFileTransformer,Runnable {
    private static ClassUploadTransformer ourInstance = new ClassUploadTransformer();

    // 暂定最大10m
    public final static int MAX_DUMP_CLASS_SIZE = 1024 * 1024 * 10;

    public final static int MAX_HASH_SIZE = 1024*2;

    /**
     * class for dump;
     */
    private Class<?> clazzToUpload = null;
    /**
     * transId for dump;
     */
    private String transId = null;

    /*
     * client to send class
     */
    private Client client = null;
    private Instrumentation inst = null;
    private Thread uploadClassThread = null;

    private boolean started = false;
    private boolean notifyStop = false;

    /**
     * send class info Queue lock
     */

    private ReentrantLock   classToUploadLock = null;

    private Condition classToUploadcondition = null;

    /*
     *  class hash cache lock
     */

    private ReadWriteLock classHashCachelock = null;

    /*
     * class hash cache
     */

    private LinkedHashMap<Integer, Integer> classHashCache = null;

    /**
     * send class info Queue
     */

    private Queue<SendClassInfo> classToUploadList = null;

    public static  ClassUploadTransformer getInstance() {
        if(ourInstance == null) {
            ourInstance = new ClassUploadTransformer();
        }

        return ourInstance;
    }

    public static void delInstance() {
        if(ourInstance != null) {
            ourInstance.stop();
            ourInstance = null;
        }
    }

    public ClassUploadTransformer() {
        
    }

    public void run() {
        System.out.println("run enter");

        try {
            while(true) {
                System.out.println("thread start receive");
                SendClassInfo info = getUploadClassInfo_Wait();
                if(notifyStop) {
                    break;
                }

                if(info == null) {
                    System.out.println("info == null");
                    continue;
                }

                try {
                    System.out.println("start processing");

                    this.clazzToUpload = info.clazz;
                    this.transId = info.transId;
    
                    if (inst.isModifiableClass(info.clazz) && !info.clazz.getName().startsWith("java.lang.invoke.LambdaForm")) {
                        try {
                            inst.retransformClasses(info.clazz);
                        } catch (Exception e) {
                            SmithLogger.exception(e);
                        }
                    }
                }
                finally {
                    this.clazzToUpload = null;
                    this.transId = null;
                    info = null;
                }
            }
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        System.out.println("run leave");
    }

    public synchronized boolean start(Client client,Instrumentation inst) {
        System.out.println("start enter");

        if(!started) {
            try {
                this.client = client;
                this.inst = inst;
    
                inst.addTransformer(ourInstance, true);
                System.out.println("addTransformer success");
                this.classToUploadLock = new ReentrantLock();
                this.classToUploadcondition = this.classToUploadLock.newCondition();
                this.classHashCachelock = new ReentrantReadWriteLock();
                this.classHashCache = new LinkedHashMap<Integer, Integer>(MAX_HASH_SIZE, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(Map.Entry<Integer, Integer> eldest) {
                        return size() > MAX_HASH_SIZE;
                    };
                };
                this.classToUploadList = new LinkedList<>();

                System.out.println("init ClassUploadTransformer Var success");

                uploadClassThread = new Thread(ourInstance);

                uploadClassThread.start();

                System.out.println("Start  uploadClassThread success");

                started = true;
            }
            catch(Exception e) {
                SmithLogger.exception(e);
                inst.removeTransformer(ourInstance);
                this.classToUploadcondition = null;
                this.classToUploadLock = null;
                this.classHashCachelock = null;
                this.classHashCache = null;
                this.classToUploadList = null;
                this.uploadClassThread = null;
                this.client = null;
                this.inst = null;
            }
        }

        System.out.println("start leave");

        return started;
    }

    public synchronized boolean stop() {
        System.out.println("stop enter");

        if(started)  {
            try {
                started = false;
                inst.removeTransformer(ourInstance);

                System.out.println("removeTransformer success");

                System.out.println("clear classHashCache");
                classHashCachelock.writeLock().lock();
                try {
                    classHashCache.clear();
                } finally {
                    classHashCachelock.writeLock().unlock();
                }

                System.out.println("notify thread stop");
                classToUploadLock.lock();
                try {
                    notifyStop = true;
                    classToUploadcondition.signal();
                }
                finally {
                    classToUploadLock.unlock();
                }

                System.out.println("wait thread stop");
                uploadClassThread.join();
                System.out.println("upload thread stop");

                System.out.println("clear classToUploadList");
                classToUploadLock.lock();
                try {
                    classToUploadList.clear();
                }
                finally {
                    classToUploadLock.unlock();
                }
    
                this.uploadClassThread = null;
                this.client = null;
                this.inst = null;
                this.classToUploadcondition = null;
                this.classToUploadLock = null;
                this.classHashCachelock = null;
                this.classHashCache = null;
                this.classToUploadList = null;
            }
            catch(Exception e) {
                SmithLogger.exception(e);
            }
        }

        System.out.println("stop leave");

        return !started;
    }

    private boolean classIsSended(int hashcode) {
        System.out.println("classIsSended enter");

        boolean isSended = false;
        classHashCachelock.readLock().lock();
        try {
            isSended = classHashCache.containsKey(hashcode);
        } finally {
            classHashCachelock.readLock().unlock();
        }

        System.out.println("classIsSended leave");

        return isSended;
    }

    private SendClassInfo getUploadClassInfo_Wait() {
        SendClassInfo ret = null;
        boolean     exceptioned = false;

        System.out.println("getUploadClassInfo_Wait enter");

        classToUploadLock.lock();
        try {
            if(classToUploadList.isEmpty()) {
                try {
                    classToUploadcondition.await();
                }
                catch(InterruptedException e) {
                    exceptioned = true;
                    SmithLogger.exception(e);
                }
            }

            if(!exceptioned && !classToUploadList.isEmpty()) {
                ret = classToUploadList.poll();
            }
        }
        finally {
            classToUploadLock.unlock();
        }

        System.out.println("getUploadClassInfo_Wait leave");

        return ret;
    }

    private boolean addUploadClassInfo(Class<?> classToUpload, String transId) {
        System.out.println("addUploadClassInfo enter");

        boolean ret = false;

        try {
            SendClassInfo info = new SendClassInfo(classToUpload,transId);
            if(info != null) {
                SmithLogger.logger.info("upload Class:" + classToUpload + "  transId:"+transId);
                classToUploadLock.lock();
                try {
                    System.out.println("add send class info:"+info);
                    classToUploadList.add(info);
                    classToUploadcondition.signal();
                }
                finally {
                    classToUploadLock.unlock();
                }

                classHashCachelock.writeLock().lock();
                try {
                    System.out.println("add class hash:"+classToUpload.hashCode());
                    classHashCache.put(classToUpload.hashCode(), 1);
                } finally {
                    classHashCachelock.writeLock().unlock();
                }

                ret = true;
            }
        }
        catch(Exception e) {
            e.printStackTrace();
        }

        System.out.println("addUploadClassInfo leave");

        return ret;
    }

    public  boolean sendClass(Class<?> clazz, String transId) {
        System.out.println("sendClass enter");

        boolean ret = false;

        if(!started) {
            System.out.println("sendClass !started leave");
            return false;
        }

        try {
            if(!classIsSended(clazz.hashCode())) {
                ret = addUploadClassInfo(clazz,transId);
            }
            else {
                ret = true;
            }
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        System.out.println("sendClass leave");

        return ret;
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer)
            throws IllegalClassFormatException {

        if (clazzToUpload == classBeingRedefined) {
            sendClass(classBeingRedefined, classfileBuffer);
        }

        return null;
    }

    /**
     * dump Class;
     * @param clazz
     * @param data
     */
    private void sendClass(Class<?> clazz, byte[] data) {

        try {
            if(clazz != null &&
               data != null &&
               data.length < MAX_DUMP_CLASS_SIZE) {

                int length = data.length;
                ClassUpload classUpload = new ClassUpload();
                classUpload.setTransId(transId);

                // TODO 第一版先不分包，看下性能
                classUpload.setByteTotalLength(length);
                classUpload.setByteLength(length);
                classUpload.setClassData(data);

                if (client != null) {
                    client.write(Operate.CLASSUPLOAD, classUpload);
                    SmithLogger.logger.info("send classdata: " + classUpload.toString());
                }
            }

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

}
