package com.security.smith.client;

public class SendClassInfo {
    public Class<?> clazz;
    
    public String transId;

    public SendClassInfo(Class<?> classToUpload, String transId) {
        this.clazz = classToUpload;
        this.transId = transId;
    }
}