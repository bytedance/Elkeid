package com.security.smith.client.message;

import java.util.Arrays;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.util.StdConverter;

public class ClassUpload {

    private String trans_id;
    private int byte_totallength;
    private int byte_offset;
    private int byte_length;
    
    @JsonSerialize(converter = ClassFilterConverter.class)
    private ClassFilter metadata;
    private byte[] class_data;

    public String getTransId() {
        return trans_id;
    }

    public void setTransId(String trans_id) {
        this.trans_id = trans_id;
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

    public byte[] getClassData() {
        return class_data;
    }

    public void setClassData(byte[] class_data) {
        this.class_data = class_data;
    }

}

class ClassFilterConverter extends StdConverter<StackTraceElement[], String[]> {
    @Override
    public String[] convert(StackTraceElement[] value) {
        if (value.length <= 2)
            return null;

        return Arrays.stream(Arrays.copyOfRange(value, 2, value.length))
                .map(StackTraceElement::toString)
                .toArray(String[]::new);
    }
}