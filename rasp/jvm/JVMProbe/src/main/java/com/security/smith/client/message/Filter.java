package com.security.smith.client.message;

public class Filter {
    private int classID;
    private int methodID;
    private MatchRule[] include;
    private MatchRule[] exclude;

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

    public MatchRule[] getInclude() {
        return include;
    }

    public void setInclude(MatchRule[] include) {
        this.include = include;
    }

    public MatchRule[] getExclude() {
        return exclude;
    }

    public void setExclude(MatchRule[] exclude) {
        this.exclude = exclude;
    }
}
