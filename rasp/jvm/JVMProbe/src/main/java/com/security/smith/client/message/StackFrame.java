package com.security.smith.client.message;

public class StackFrame {
    public enum Operator {
        OR,
        AND
    }

    private String[] keywords;
    private Operator operator;

    public String[] getKeywords() {
        return keywords;
    }

    public void setKeywords(String[] keywords) {
        this.keywords = keywords;
    }

    public Operator getOperator() {
        return operator;
    }

    public void setOperator(Operator operator) {
        this.operator = operator;
    }
}
