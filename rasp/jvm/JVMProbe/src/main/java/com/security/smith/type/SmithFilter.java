package com.security.smith.type;

public class SmithFilter {
    private int classID;
    private int methodID;
    private SmithMatchRule[] include;
    private SmithMatchRule[] exclude;

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

    public SmithMatchRule[] getInclude() {
        return include;
    }

    public void setInclude(SmithMatchRule[] include) {
        this.include = include;
    }

    public SmithMatchRule[] getExclude() {
        return exclude;
    }

    public void setExclude(SmithMatchRule[] exclude) {
        this.exclude = exclude;
    }
}
