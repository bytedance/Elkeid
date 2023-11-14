package com.security.smith.client.message;

public class ClassDump {
    private Integer rule_id;
    private String trans_id;
    private int byte_totallength;
    private int byte_length;
    private byte[] class_data;

    public Integer getRuleId() {
        return rule_id;
    }

    public void setRuleId(Integer rule_id) {
        this.rule_id = rule_id;
    }

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