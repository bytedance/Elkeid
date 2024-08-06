package com.security.smith.client.message;

import com.google.gson.annotations.SerializedName;
import java.time.Instant;
import java.util.UUID;

public class ClassFilter {
    private String trans_id = "";
    private String class_name = "";
    private String class_path = "";
    private String interfaces_name = "";
    private String class_loader_name = "";
    private String parent_class_name = "";
    private String parent_class_loader_name = "";
    private long rule_id = -1;
    private int class_id = -1;
    private int method_id = -1;
    private String types = "";
    @SerializedName("stackTrace")
    private StackTraceElement[] stack_trace = {};

    public String getTransId() {
        return trans_id;
    }

    public void setTransId() {
        UUID uniqueId = UUID.randomUUID();
        this.trans_id = uniqueId.toString().replace("-", "");
    }

    public String getClassName() {
        return class_name;
    }

    public void setClassName(String className) {
        this.class_name = className;
    }

    public String getClassPath() {
        return class_path;
    }

    public void setClassPath(String classPath) {
        this.class_path = classPath;
    }

    public String getInterfacesName() {
        return interfaces_name;
    }

    public void setInterfacesName(String interfacesName) {
        this.interfaces_name = interfacesName;
    }

    public String getClassLoaderName() {
        return class_loader_name;
    }

    public void setClassLoaderName(String classLoaderName) {
        this.class_loader_name = classLoaderName;
    }

    public String getParentClassName() {
        return parent_class_name;
    }

    public void setParentClassName(String parentClassName) {
        this.parent_class_name = parentClassName;
    }

    public String getParentClassLoaderName() {
        return parent_class_loader_name;
    }

    public void setParentClassLoaderName(String parentClassLoaderName) {
        this.parent_class_loader_name = parentClassLoaderName;
    }

    public long getRuleId() {
        return rule_id;
    }

    public void setRuleId(long ruleId) {
        this.rule_id = ruleId;
    }

    public int getClassId() {
        return class_id;
    }

    public void setClassId(int classId) {
        this.class_id = classId;
    }

    public int getMethodId() {
        return method_id;
    }

    public void setMethodId(int methodId) {
        this.method_id = methodId;
    }

    public String getTypes() {
        return types;
    }

    public void setTypes(String types) {
        this.types = types;
    }

    public StackTraceElement[] getStackTrace() {
        return stack_trace;
    }

    public void setStackTrace(StackTraceElement[] stackTrace) {
        this.stack_trace = stackTrace;
    }

    @Override
    public String toString() {
        return "{" +
                "trans_id: '" + trans_id + '\'' +
                ", class_id: '" + class_id + '\'' +
                ", method_id: '" + method_id + '\'' +
                ", types: '" + types + '\'' +
                ", class_name: '" + class_name + '\'' +
                ", class_path: '" + class_path + '\'' +
                ", interfaces_name: '" + interfaces_name + '\'' +
                ", class_loader_name: '" + class_loader_name + '\'' +
                ", parent_class_name: '" + parent_class_name + '\'' +
                ", parent_class_loader_name: '" + parent_class_loader_name + '\'' +
                ", rule_id: " + rule_id +
                ", timestamp: " + Instant.now().getEpochSecond() +
                '}';
    }
}