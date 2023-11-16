package com.security.smith.client;

import java.util.ArrayList;
import java.util.Arrays;

public class Rule_Json {
    private  int rule_version;
    private Rule_Item[] rule;

    public  Rule_Json() {

    }

    public  Rule_Json(int rule_version,Rule_Item[] rule) {
        this.rule_version = rule_version;
        this.rule = new Rule_Item[rule.length];

        System.arraycopy(this.rule,0,rule,0,rule.length);
    }

    public int getRule_version() {
        return this.rule_version;
    }

    public void setRule_version(int rule_version) {
        this.rule_version = rule_version;
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
