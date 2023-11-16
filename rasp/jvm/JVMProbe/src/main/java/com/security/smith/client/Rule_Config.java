package com.security.smith.client;

import com.security.smith.log.SmithLogger;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

public class Rule_Config {
    private static ObjectMapper m_objectMapper = new ObjectMapper();
    private static Rule_Json m_Rule_Json;

    private static Rule_Mgr  m_Rule_Mgr;

    public Rule_Config() {
        m_Rule_Json = null;
        m_Rule_Mgr = null;
    }

    public Rule_Config(Rule_Mgr RuleMgr) {
        m_Rule_Json = null;
        m_Rule_Mgr = RuleMgr;
    }

    public static void setRuleMgr(Rule_Mgr RuleMgr) {
        m_Rule_Mgr = RuleMgr;
    }

    public static boolean setRuleConfig(String JsonRule) {
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
