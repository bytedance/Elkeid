package com.security.smith.type;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.util.StdConverter;

import java.util.Arrays;

public class SmithTrace {
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

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public Object getRet() {
        return ret;
    }

    public void setRet(Object ret) {
        this.ret = ret;
    }

    public Object[] getArgs() {
        return args;
    }

    public void setArgs(Object[] args) {
        this.args = args;
    }

    public StackTraceElement[] getStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(StackTraceElement[] stackTrace) {
        this.stackTrace = stackTrace;
    }

    private int classID;
    private int methodID;
    private boolean blocked;

    @JsonSerialize(converter = RetConverter.class)
    private Object ret;

    @JsonSerialize(converter = ArgsConverter.class)
    private Object[] args;

    @JsonSerialize(converter = StackTraceConverter.class)
    private StackTraceElement[] stackTrace;
}

class RetConverter extends StdConverter<Object, String> {
    @Override
    public String convert(Object value) {
        return String.valueOf(value);
    }
}

class StackTraceConverter extends StdConverter<StackTraceElement[], String[]> {
    @Override
    public String[] convert(StackTraceElement[] value) {
        if (value.length <= 2)
            return null;

        return Arrays.stream(Arrays.copyOfRange(value, 2, value.length))
                .map(StackTraceElement::toString)
                .toArray(String[]::new);
    }
}

class ArgsConverter extends StdConverter<Object[], String[]> {
    @Override
    public String[] convert(Object[] value) {
        return Arrays.stream(value).map(String::valueOf).toArray(String[]::new);
    }
}
