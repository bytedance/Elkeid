package com.security.smith.client.message;

import java.time.Instant;

public class ClassUpload {

    private String trans_id = "";
    private int byte_total_length;
    private int byte_offset;
    private int byte_length;
    private String class_data = "";

    public String getTransId() {
        return trans_id;
    }

    public void setTransId(String traceId) {
        this.trans_id = traceId;
    }

    public int getByte_Total_Length() {
        return byte_total_length;
    }

    public void setByteTotalLength(int byteTotallength) {
        this.byte_total_length = byteTotallength;
    }

    public int getByteOffset() {
        return byte_offset;
    }

    public void setByteOffset(int byteOffset) {
        this.byte_offset = byteOffset;
    }

    public int getByteLength() {
        return byte_length;
    }

    public void setByteLength(int byteLength) {
        this.byte_length = byteLength;
    }

    public String getClassData() {
        return class_data;
    }

    public void setClassData(String class_data) {
        this.class_data = class_data;
    }

    @Override
    public String toString() {
        return "{" +
                "transId: '" + trans_id + '\'' +
                ", byteTotalLength: " + byte_total_length +
                ", byteOffset: " + byte_offset +
                ", byteLength: " + byte_length +
                ", timestamp: " + Instant.now().getEpochSecond() +
                ", classData: " + class_data +
                '}';
    }
}