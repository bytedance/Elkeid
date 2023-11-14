package com.security.smith.client.message;


import com.fasterxml.jackson.databind.annotation.JsonSerialize;


public class ClassFilter {
    private String class_name;
    private String class_path;
    private String super_class;
    private String class_loader_name;
    private String base_class_name;
    private String base_class_loader_name;
    private int rule_id;

    @JsonSerialize(converter = StackTraceConverter.class)
    private StackTraceElement[] stackTrace;

    public String getClassName() {
        return class_name;
    }

    public void setClassName(String class_name) {
        this.class_name = class_name;
    }

    public String getClassPath() {
        return class_path;
    }

    public void setClassPath(String class_path) {
        this.class_path = class_path;
    }

    public String getSuperClass() {
        return super_class;
    }

    public void setSuperClass(String super_class) {
        this.super_class = super_class;
    }

    public String getClassLoaderName() {
        return class_loader_name;
    }

    public void setClassLoaderName(String class_loader_name) {
        this.class_loader_name = class_loader_name;
    }

    public String getBaseClassName() {
        return base_class_name;
    }

    public void setBaseClassName(String base_class_name) {
        this.base_class_name = base_class_name;
    }

    public String getBaseClassLoaderName() {
        return base_class_loader_name;
    }

    public void setBaseClassLoaderName(String base_class_loader_name) {
        this.base_class_loader_name = base_class_loader_name;
    }

    public int getRuleId() {
        return rule_id;
    }

    public void setRuleId(int rule_id) {
        this.rule_id = rule_id;
    }

    public StackTraceElement[] getStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(StackTraceElement[] stackTrace) {
        this.stackTrace = stackTrace;
    }

}