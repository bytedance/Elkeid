package com.security.smith.client;

import java.util.ArrayList;
import java.util.Arrays;

public class Rule_Item {
    private String virusName;
    private long flags;

    private long rule_id;

    private String className;

    private String classPath;

    private String interfacesName;

    private String classLoaderName;

    private String parentClassName;

    private String virusSignature;

    public Rule_Item() {

    }

    public Rule_Item(Rule_Item RuleItem) {
        this.virusName = RuleItem.getVirusName();;
        this.flags = RuleItem.getFlags();
        this.rule_id = RuleItem.getRule_id();
        this.className = RuleItem.getClassName();
        this.classPath = RuleItem.getClassPath();
        this.interfacesName = RuleItem.getInterfacesName();
        this.classLoaderName = RuleItem.getClassLoaderName();
        this.parentClassName = RuleItem.getParentClassName();
        this.virusSignature = RuleItem.getVirusSignature();
    }

    public Rule_Item(
            String virusName,
            long flags,
            long rule_id,
            String className,
            String classPath,
            String interfacesName,
            String classLoaderName,
            String parentClassName,
            String virusSignature) {
        this.virusName = virusName;;
        this.flags = flags;
        this.rule_id = rule_id;
        this.className = className;
        this.classPath = classPath;
        this.interfacesName = interfacesName;
        this.classLoaderName = classLoaderName;
        this.parentClassName = parentClassName;
        this.virusSignature = virusSignature;
    }

    public String getVirusName() {
        return this.virusName;
    }

    public void setVirusName(String virusName) {
        this.virusName = virusName;
    }

    public long getFlags() {
        return this.flags;
    }

    public void setFlags(long flags) {
        this.flags = flags;
    }

    public long getRule_id() {
        return rule_id;
    }

    public void setRule_id(long rule_id) {
        this.rule_id = rule_id;
    }

    public String getClassName() {
        return this.className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String getClassPath() {
        return this.classPath;
    }

    public void setClassPath(String classPath) {
        this.classPath = classPath;
    }

    public String getInterfacesName() {
        return this.interfacesName;
    }

    public void setInterfacesName(String interfacesName) {
        this.interfacesName = interfacesName;
    }

    public String getClassLoaderName() {
        return this.classLoaderName;
    }

    public void setClassLoaderName(String classLoaderName) {
        this.classLoaderName = classLoaderName;
    }

    public String getParentClassName() {
        return this.parentClassName;
    }

    public void setParentClassName(String parentClassName) {
        this.parentClassName = parentClassName;
    }

    public String getVirusSignature() {
        return this.virusSignature;
    }

    public void setVirusSignature(String virusSignature) {
        this.virusSignature = virusSignature;
    }

}
