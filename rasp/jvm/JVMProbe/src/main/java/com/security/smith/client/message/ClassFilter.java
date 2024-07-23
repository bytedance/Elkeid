package com.security.smith.client.message;

import com.google.gson.annotations.SerializedName;
import java.time.Instant;
import java.util.UUID;

public class ClassFilter {
    private String transId = null;
    private String className = "";
    private String classPath = "";
    private String interfacesName = "";
    private String classLoaderName = "";
    private String parentClassName = "";
    private String parentClassLoaderName = "";
    private long ruleId;
    @SerializedName("stackTrace")
    private StackTraceElement[] stackTrace = {};

    public String getTransId() {
        return transId;
    }

    public void setTransId() {
        UUID uniqueId = UUID.randomUUID();
        transId = uniqueId.toString().replace("-", "");
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String getClassPath() {
        return classPath;
    }

    public void setClassPath(String classPath) {
        this.classPath = classPath;
    }

    public String getInterfacesName() {
        return interfacesName;
    }

    public void setInterfacesName(String interfacesName) {
        this.interfacesName = interfacesName;
    }

    public String getClassLoaderName() {
        return classLoaderName;
    }

    public void setClassLoaderName(String classLoaderName) {
        this.classLoaderName = classLoaderName;
    }

    public String getParentClassName() {
        return parentClassName;
    }

    public void setParentClassName(String parentClassName) {
        this.parentClassName = parentClassName;
    }

    public String getParentClassLoaderName() {
        return parentClassLoaderName;
    }

    public void setParentClassLoaderName(String parentClassLoaderName) {
        this.parentClassLoaderName = parentClassLoaderName;
    }

    public long getRuleId() {
        return ruleId;
    }

    public void setRuleId(long ruleId) {
        this.ruleId = ruleId;
    }

    public StackTraceElement[] getStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(StackTraceElement[] stackTrace) {
        this.stackTrace = stackTrace;
    }

    @Override
    public String toString() {
        return "{" +
                "transId: '" + transId + '\'' +
                ", className: '" + className + '\'' +
                ", classPath: '" + classPath + '\'' +
                ", interfacesName: '" + interfacesName + '\'' +
                ", classLoaderName: '" + classLoaderName + '\'' +
                ", parentClassName: '" + parentClassName + '\'' +
                ", parentClassLoaderName: '" + parentClassLoaderName + '\'' +
                ", ruleId: " + ruleId +
                ", timestamp: " + Instant.now().getEpochSecond() +
                '}';
    }
}