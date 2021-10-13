package com.security.smith.type;

public class SmithBlock {
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

    public SmithMatchRule[] getRules() {
        return rules;
    }

    public void setRules(SmithMatchRule[] rules) {
        this.rules = rules;
    }

    private int classID;
    private int methodID;
    private SmithMatchRule[] rules;
}
