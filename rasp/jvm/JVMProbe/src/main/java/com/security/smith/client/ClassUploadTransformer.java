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
        SmithLogger.logger.info("class upload thread run enter");

        try {
            while(true) {
                SendClassInfo info = getUploadClassInfo_Wait();
                if(notifyStop) {
                    SmithLogger.logger.info("class upload thread stop!");
                    break;
                }

                if(info == null) {
                    continue;
                }

                try {
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

        SmithLogger.logger.info("class upload thread run leave");
    }

    public synchronized boolean start(Client client,Instrumentation inst) {
        SmithLogger.logger.info("start enter");

        if(!started) {
            try {
                this.client = client;
                this.inst = inst;
    
                inst.addTransformer(ourInstance, true);
                SmithLogger.logger.info("addTransformer success");
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

                SmithLogger.logger.info("init ClassUploadTransformer Var success");

                uploadClassThread = new Thread(ourInstance);

                uploadClassThread.start();

                SmithLogger.logger.info("Start  uploadClassThread success");

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

        SmithLogger.logger.info("start leave");

        return started;
    }

    public synchronized boolean stop() {
        SmithLogger.logger.info("stop enter");

        if(started)  {
            try {
                started = false;
                inst.removeTransformer(ourInstance);

                SmithLogger.logger.info("removeTransformer success");

                SmithLogger.logger.info("clear classHashCache");
                classHashCachelock.writeLock().lock();
                try {
                    classHashCache.clear();
                } finally {
                    classHashCachelock.writeLock().unlock();
                }

                SmithLogger.logger.info("notify thread stop");
                classToUploadLock.lock();
                try {
                    notifyStop = true;
                    classToUploadcondition.signal();
                }
                finally {
                    classToUploadLock.unlock();
                }

                SmithLogger.logger.info("wait thread stop");
                uploadClassThread.join();
                SmithLogger.logger.info("upload thread stoped");

                SmithLogger.logger.info("clear classToUploadList");
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

        SmithLogger.logger.info("stop leave");

        return !started;
    }

    private boolean classIsSended(int hashcode) {
        boolean isSended = false;
        classHashCachelock.readLock().lock();
        try {
            isSended = classHashCache.containsKey(hashcode);
        } finally {
            classHashCachelock.readLock().unlock();
        }

        return isSended;
    }

    private SendClassInfo getUploadClassInfo_Wait() {
        SendClassInfo ret = null;
        boolean     exceptioned = false;

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

        return ret;
    }

    private boolean addUploadClassInfo(Class<?> classToUpload, String transId) {
        boolean ret = false;

        try {
            SendClassInfo info = new SendClassInfo(classToUpload,transId);
            if(info != null) {
                SmithLogger.logger.info("upload Class:" + classToUpload + "  transId:"+transId);
                classToUploadLock.lock();
                try {
                    classToUploadList.add(info);
                    classToUploadcondition.signal();
                }
                finally {
                    classToUploadLock.unlock();
                }

                classHashCachelock.writeLock().lock();
                try {
                    classHashCache.put(classToUpload.hashCode(), 1);
                } finally {
                    classHashCachelock.writeLock().unlock();
                }

                ret = true;
            }
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        return ret;
    }

    public  boolean sendClass(Class<?> clazz, String transId) {
        boolean ret = false;

        if(!started) {
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
