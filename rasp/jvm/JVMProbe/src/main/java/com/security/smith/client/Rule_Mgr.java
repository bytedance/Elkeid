package com.security.smith.client;

import com.security.smith.client.message.*;
import com.security.smith.log.SmithLogger;

import java.util.ArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Rule_Mgr {
    private static int m_rule_version;
    final private static ArrayList<Rule_Scanner>     m_ruleList = new ArrayList<Rule_Scanner>();
    final private static ReadWriteLock m_ruleLock = new ReentrantReadWriteLock();

    public static void setVersion(int rule_version) {
        m_rule_version = rule_version;
    }

    public static int getVersion() {
        return m_rule_version;
    }

    public static boolean addRule(
            Rule_Scanner rule) {
        boolean bresult = false;

        try {
            m_ruleLock.writeLock().lock();

            try {
                bresult = m_ruleList.add(rule);
            }
            catch(Exception e) {
                SmithLogger.exception(e);
            }
    
        }
        finally {
            m_ruleLock.writeLock().unlock();
        }

        
        return bresult;
    }

    public static void delRule_all() {
        try {
            m_ruleLock.writeLock().lock();
            try {
                
                m_ruleList.clear();
            }
            catch(Exception e) {
                SmithLogger.exception(e);
            }
        }
        finally {
            m_ruleLock.writeLock().unlock();
        }
    }

    public static long matchRule(ClassFilter Data) {
        long rule_id = -1;

        try {
            m_ruleLock.readLock().lock();

            for (int i = 0;i < m_ruleList.size();i++) {
                Rule_Scanner rule = m_ruleList.get(i);
    
                rule_id = rule.matchRule(Data);
                if(rule_id != -1) {
                    break;
                }
            }
        }
        finally {
            m_ruleLock.readLock().unlock();
        }

        return rule_id;
    }
}
