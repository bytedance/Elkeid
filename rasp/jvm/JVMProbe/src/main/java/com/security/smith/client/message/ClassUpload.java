package com.security.smith.client.message;

import java.util.Arrays;
import java.util.UUID;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.util.StdConverter;

public class ClassUpload {

    private String trans_id;
    private int byte_totallength;
    private int byte_offset;
    private int byte_length;
    
    private ClassFilter metadata;
    private byte[] class_data;

    public String getTransId() {
        return trans_id;
    }

    public void setTransId() {
        UUID uniqueId = UUID.randomUUID();
        trans_id = uniqueId.toString().replace("-", "");
    }

    public int getByteTotalLength() {
        return byte_totallength;
    }

    public void setByteTotalLength(int byte_totallength) {
        this.byte_totallength = byte_totallength;
    }

    public int getByteOffset() {
        return byte_offset;
    }

    public void setByteOffset(int byte_offset) {
        this.byte_offset = byte_offset;
    }

    public int getByteLength() {
        return byte_length;
    }

    public void setByteLength(int byte_length) {
        this.byte_length = byte_length;
    }

    public ClassFilter getMetaData() {
        return metadata;
    }

    public void setMetadata(ClassFilter metadata) {
        this.metadata = metadata;
    }

    public byte[] getClassData() {
        return class_data;
    }

    public void setClassData(byte[] class_data) {
        this.class_data = class_data;
    }

}