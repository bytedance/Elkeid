package com.security.smith.client;

import java.lang.instrument.ClassFileTransformer;
import java.lang.Class;

import java.security.ProtectionDomain;

import com.security.smith.client.message.ClassFilter;
import com.security.smith.client.message.ClassUpload;
import com.security.smith.log.SmithLogger;

import java.lang.instrument.IllegalClassFormatException;

public class ClassUploadTransformer implements ClassFileTransformer {
    // 暂定最大10m
    public final static int MAX_DUMP_CLASS_SIZE = 1024 * 1024 * 10;

    /**
     * class for dump;
     */
    private Class<?> clazzToUpload = null;

    /*
     * client to send class
     */
    private Client client = null;

    /*
     * class information 
     */
    private ClassFilter classFilter = null;


    public ClassUploadTransformer(Class<?> classToUpload, Client client, ClassFilter classFilter) {
        this.clazzToUpload = classToUpload;
        this.client = client;
        this.classFilter = classFilter;
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
                classUpload.setTransId();

                // TODO 第一版先不分包，看下性能
                classUpload.setByteTotalLength(length);
                classUpload.setByteLength(length);
                classUpload.setClassData(data);
                if (classFilter != null) {
                    classUpload.setMetadata(classFilter);
                }
                if (client != null) {
                    client.write(Operate.CLASSUPLOAD, classUpload);
                }
            }

        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

}
