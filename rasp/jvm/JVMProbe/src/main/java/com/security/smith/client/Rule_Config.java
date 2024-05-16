package com.security.smith.client;

import com.security.smith.log.SmithLogger;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

public class Rule_Config {
    private ObjectMapper m_objectMapper = new ObjectMapper();
    private Rule_Json m_Rule_Json;

    private Rule_Mgr  m_Rule_Mgr;

    public Rule_Config() {
        m_Rule_Json = null;
        m_Rule_Mgr = null;
    }

    public Rule_Config(Rule_Mgr RuleMgr) {
        m_Rule_Json = null;
        m_Rule_Mgr = RuleMgr;
    }

    public void setRuleMgr(Rule_Mgr RuleMgr) {
        m_Rule_Mgr = RuleMgr;
    }

    public boolean setVersion(int rule_version) {
        if(m_Rule_Mgr == null) {
            return false;
        }

        m_Rule_Mgr.delRule_all();
        m_Rule_Mgr.setVersion(rule_version);

        return true;
    }

    public void destry() {
        try {
            m_Rule_Json = null;
            m_objectMapper = null;
            m_Rule_Mgr.delRule_all();
            m_Rule_Mgr = null;
        } catch (Exception e) {
        }
    }

    public void printRule(Rule_Scanner RuleScanner) {
        System.out.println("Add RuleItem:" + RuleScanner);
        System.out.println("ruleId:" + RuleScanner.m_ruleId);
        System.out.println("virusName:" + RuleScanner.m_virusName);
        System.out.println("className:" + RuleScanner.m_className);
        System.out.println("classPath:" + RuleScanner.m_classPath);
        System.out.println("interfaceName:" + RuleScanner.m_interfaceName);
        System.out.println("classLoaderName:" + RuleScanner.m_classLoaderName);
        System.out.println("parentClassName:" + RuleScanner.m_parentClassName);
    }

    public boolean addRuleData(Rule_Data ruleData) {
        boolean bresult = false;

        if(m_Rule_Mgr == null) {
            return false;
        }

        try {
                SmithLogger.logger.info("ruleconfig.AddRuleData Entry---------------------------");
                Rule_Item[] rule = ruleData.getRule();

                for (int i = 0;i < rule.length;i++) {
                    Rule_Item RuleItem = rule[i];
                    Rule_Scanner RuleScanner = new Rule_Scanner(RuleItem);
                    if(RuleScanner == null) {
                        continue;
                    }

                    RuleScanner.setVersion(m_Rule_Mgr.getVersion());

                    //printRule(RuleScanner);

                    m_Rule_Mgr.addRule(RuleScanner);

                    bresult = true;
                }
                SmithLogger.logger.info("ruleconfig.AddRuleData Leave ---------------------------");
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        return bresult;
    }

    public boolean setRuleConfig(String JsonRule) {
        boolean bresult = false;

        if(m_Rule_Mgr == null) {
            return false;
        }

        try {
            m_objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,false);

            m_Rule_Json = m_objectMapper.readValue(JsonRule, Rule_Json.class);
            if(m_Rule_Json != null && m_Rule_Json.getRule().length > 0) {
                int rule_version = m_Rule_Json.getRule_version();
                Rule_Item[] rule = m_Rule_Json.getRule();

                m_Rule_Mgr.delRule_all();

                for (int i = 0;i < rule.length;i++) {
                    Rule_Item RuleItem = rule[i];
                    Rule_Scanner RuleScanner = new Rule_Scanner(RuleItem);
                    if(RuleScanner == null) {
                        continue;
                    }

                    RuleScanner.setVersion(rule_version);

                    m_Rule_Mgr.addRule(RuleScanner);
                }
            }

            bresult = true;
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        return bresult;
    }
}
