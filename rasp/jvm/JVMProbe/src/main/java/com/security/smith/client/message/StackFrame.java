package com.security.smith.client.message;

public class StackFrame {
    public static final int OR = 0;
    public static final int AND = 1;
    /* 
    public enum Operator {
        OR,
        AND
    }
    */

    private String[] keywords;
    private int operator;

    public String[] getKeywords() {
        return keywords;
    }

    public void setKeywords(String[] keywords) {
        this.keywords = keywords;
    }

    public int getOperator() {
        return operator;
    }

    public void setOperator(int operator) {
        this.operator = operator;
    }
}
