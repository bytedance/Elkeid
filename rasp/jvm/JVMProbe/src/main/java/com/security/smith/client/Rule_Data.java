package com.security.smith.client;

public class Rule_Data {
    private Rule_Item[] rule;

    public Rule_Data() {

    }

    public Rule_Item[] getRule() {
        return this.rule;
    }

    public void setRule(Rule_Item[] rule) {
        this.rule = new Rule_Item[rule.length];

        for(int i = 0;i < rule.length;i++) {
            this.rule[i] = new Rule_Item(rule[i]);
        }
    }
}
