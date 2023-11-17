package com.security.smith.client.message;


public class ClassUpload {

    private String transId;
    private int byteTotalLength;
    private int byteOffset;
    private int byteLength;
    private byte[] classData;

    public String getTransId() {
        return transId;
    }

    public void setTransId(String traceId) {
        this.transId = traceId;
    }

    public int getByteTotalLength() {
        return byteTotalLength;
    }

    public void setByteTotalLength(int byteTotallength) {
        this.byteTotalLength = byteTotallength;
    }

    public int getByteOffset() {
        return byteOffset;
    }

    public void setByteOffset(int byteOffset) {
        this.byteOffset = byteOffset;
    }

    public int getByteLength() {
        return byteLength;
    }

    public void setByteLength(int byteLength) {
        this.byteLength = byteLength;
    }

    public byte[] getClassData() {
        return classData;
    }

    public void setClassData(byte[] class_data) {
        this.classData = class_data;
    }

}