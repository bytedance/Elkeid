package com.security.smith.client.message;

public class Block {
    private int classID;
    private int methodID;
    private String policyID;
    private MatchRule[] rules;
    private StackFrame stackFrame;

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

    public String getPolicyID() {
        return policyID;
    }

    public void setPolicyID(String policyID) {
        this.policyID = policyID;
    }

    public MatchRule[] getRules() {
        return rules;
    }

    public void setRules(MatchRule[] rules) {
        this.rules = rules;
    }

    public StackFrame getStackFrame() {
        return stackFrame;
    }

    public void setStackFrame(StackFrame stackFrame) {
        this.stackFrame = stackFrame;
    }

    public void removeAll() {
        for (int i = 0; i < rules.length; i++) {
            rules[i] = null;
        }
        this.rules = null;
        stackFrame = null;
    }
}
