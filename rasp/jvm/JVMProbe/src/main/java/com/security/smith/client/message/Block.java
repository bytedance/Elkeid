package com.security.smith.client.message;

public class Block {
    private int classID;
    private int methodID;
    private MatchRule[] rules;

    public int getClassID() {
        return classID;
    }

    public void setClassID(int classID) {
        this.classID = classID;
    }

    public int getMethodID() {
        return methodID;
    }

    public void setMethodID(int methodID) {
        this.methodID = methodID;
    }

    public MatchRule[] getRules() {
        return rules;
    }

    public void setRules(MatchRule[] rules) {
        this.rules = rules;
    }
}
