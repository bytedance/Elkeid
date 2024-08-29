package com.security.smith.rulemgr;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import net.jpountz.xxhash.XXHash32;
import net.jpountz.xxhash.XXHash64;
import net.jpountz.xxhash.XXHashFactory;

import com.security.smith.log.SmithLogger;

public class StackRuleManager {
    public  Map<Integer, StackRule> stackRuleMaps = new ConcurrentHashMap<>();
    private ReadWriteLock ruleLock = new ReentrantReadWriteLock();
    private XXHashFactory factory = XXHashFactory.fastestInstance();
    private XXHash64 hash64 = factory.hash64();
    private long seed64 = 0x9747b28c727a1617L;
    private Map<Long, String> currentStack = new ConcurrentHashMap<>();


    public boolean addBlackStackRule(Integer ruleId, String[] stackinfo) {
        
        if (ruleId == null ||stackinfo == null || stackinfo.length == 0) {
            return false;
        }
        StackRule stackRule = null;
        ruleLock.readLock().lock();
        try {
            if (stackRuleMaps.containsKey(ruleId)) {
                SmithLogger.logger.info("ruleId is exist, ruleid :" + ruleId);
                stackRule = stackRuleMaps.get(ruleId);
            } else {
                SmithLogger.logger.info("ruleId is not exist, ruleid :" + ruleId);
                stackRule = new StackRule();
                stackRule.setRuleId(ruleId);
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        } finally {
            ruleLock.readLock().unlock();
        }
        
        StackItem[] items = new StackItem[stackinfo.length];
        for (int i = 0; i < stackinfo.length; i++) {
            String stack = stackinfo[i];
            if (stack != null &&!stack.isEmpty()) {
                StackItem stackItem = new StackItem();
                stackItem.setStackinfo(stack);
                stackItem.setLength(stack.length());
                if (stack.endsWith("*")) {
                    stackItem.setHashcode(0L);
                } else {
                    byte[] data = stack.getBytes(StandardCharsets.UTF_8);
                    stackItem.setHashcode(hash64.hash(data, 0, data.length, seed64));
                }
                
                items[i] = stackItem;
            }
        }
        ruleLock.writeLock().lock();
        try {
            stackRule.setBlackItems(items);
            stackRuleMaps.put(stackRule.getRuleId(), stackRule);
        } catch (Exception e) {
            SmithLogger.exception(e);
        } finally {
            ruleLock.writeLock().unlock();
        }
    
        SmithLogger.logger.info("add black stack rule: " + stackRule.getRuleId());
        return true;
    }

    public boolean addWhiteStackRule(Integer ruleId, String[] stackinfo) {
        if (ruleId == null ||stackinfo == null || stackinfo.length == 0) {
            return false;
        }
        StackRule stackRule = null;
        ruleLock.readLock().lock();
        try {
            if (stackRuleMaps.containsKey(ruleId)) {
                stackRule = stackRuleMaps.get(ruleId);
            } else {
                stackRule = new StackRule();
                stackRule.setRuleId(ruleId);
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        } finally {
            ruleLock.readLock().unlock();
        }
        
        StackItem[] items = new StackItem[stackinfo.length];
        for (int i = 0; i < stackinfo.length; i++) {
            String stack = stackinfo[i];
            if (stack!= null &&!stack.isEmpty()) {
                StackItem stackItem = new StackItem();
                stackItem.setStackinfo(stack);
                stackItem.setLength(stack.length());
                if (stack.endsWith("*")) {
                    stackItem.setHashcode(0L);
                } else {
                    byte[] data = stack.getBytes(StandardCharsets.UTF_8);
                    stackItem.setHashcode(hash64.hash(data, 0, data.length, seed64));
                }
                items[i] = stackItem;
            }
        }
        ruleLock.writeLock().lock();
        try {
            stackRule.setWhiteItems(items);
            stackRuleMaps.put(stackRule.getRuleId(), stackRule);
        } catch (Exception e) {
            SmithLogger.exception(e);
        } finally {
            ruleLock.writeLock().unlock();
        }
        
        return true;
    }

    public boolean removeBlackStackRule(Integer ruleId) {
        boolean ret = false;
        ruleLock.writeLock().lock();
        try {
            if (stackRuleMaps.containsKey(ruleId)) {
                StackRule stackRule = stackRuleMaps.get(ruleId);
                stackRule.removeBlackStackRule();
                ret = true;
    
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        } finally {
            ruleLock.writeLock().unlock();
        }
        
        return ret;
    }

    public boolean removeWhiteStackRule(Integer ruleId) {
        boolean ret = false;
        ruleLock.writeLock().lock();
        try {
            if (stackRuleMaps.containsKey(ruleId)) {
                StackRule stackRule = stackRuleMaps.get(ruleId);
                stackRule.removeWhiteStackRule();
                ret = true;
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        } finally {
            ruleLock.writeLock().unlock();
        }
    
        return ret;
    }

    public StackRule getStackRule(Integer ruleId) {
        StackRule stackRule = null;
        ruleLock.readLock().lock();
        try {
            stackRule = stackRuleMaps.get(ruleId);
        } catch (Exception e) {
            SmithLogger.exception(e);
        } finally {
            ruleLock.readLock().unlock();
        }
        return stackRule;
    }

    /**
     * Check whether the given rule ID matches the given stack information,
     * and determine the matching logic according to the isWhite flag
     *
     * @param ruleId The rule ID to check
     * @param isWhite If true, it is a positive match (all conditions must be met);
     *                if false, it is a reverse match (any condition can be met)
     * @return Returns true if the rule ID matches the stack information, and false otherwise
     */

    public boolean isMatched(Integer ruleId, boolean isWhite) {
        if (ruleId == null || !stackRuleMaps.containsKey(ruleId)) {
            SmithLogger.logger.info("ruleId is null or stackinfo is null or ruleId is not exist");
            return false;
        }
    
        try {
            if (currentStack.isEmpty()) {
                formatStack();
            }
            SmithLogger.logger.info("isWhite: " + isWhite + " ruleId: " + ruleId);
            ruleLock.readLock().lock();
            try {
                StackRule stackRule = stackRuleMaps.get(ruleId);
                if (stackRule != null) {
                    StackItem[] items = null;
                    if (isWhite) {
                        items = stackRule.getWhiteItems();
                    } else {
                        items = stackRule.getBlackItems();
                    }
                    if (items != null) {
                        for (StackItem item : items) {
                            if (item != null) {
                                SmithLogger.logger.info("item: " + item.toString());
                                if (item.getHashcode() == 0) {
                                    String stack = item.getStackinfo();
                                    for (Map.Entry<Long, String> entry : currentStack.entrySet()) {
                                        String value = entry.getValue();
                                        if (value.contains(stack.substring(0, stack.length() - 1))) {
                                            SmithLogger.logger.info("find the match, string: " + value + " hashcode: " + entry.getKey());
                                            return true;
                                        }
                                    }
                                } else {
                                    if (currentStack.containsKey(item.getHashcode())) {
                                        SmithLogger.logger.info("find the match, string: " + currentStack.get(item.getHashcode()) + " hashcode: " + item.getHashcode());
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                SmithLogger.exception(e);
            } finally {
                ruleLock.readLock().unlock();
            }
            
            SmithLogger.logger.info("not find the match");
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        return false;
    }

    public void formatStack() {
        currentStack.clear();
        SmithLogger.logger.info("currentStack size: " + currentStack.size());
        try {
            StackTraceElement[] stack_str  =  Thread.currentThread().getStackTrace();
            String[] stackTraceStrings = new String[stack_str.length];

            for (int i = 0; i < stack_str.length; i++) {
                stackTraceStrings[i] = stack_str[i].toString();
                if (stackTraceStrings[i] != null && !stackTraceStrings[i].isEmpty()) {
                    String stack = stackTraceStrings[i].replaceAll("\\(.*\\)", "");
                    byte[] data = stack.getBytes(StandardCharsets.UTF_8);
                    currentStack.put(hash64.hash(data, 0, data.length, seed64), stackTraceStrings[i]);
                }
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        return ;
    }

    public void clear() {
        ruleLock.writeLock().lock();
        for (StackRule stackRule : stackRuleMaps.values()) {
            stackRule.removeBlackStackRule();
            stackRule.removeWhiteStackRule();
        }
        SmithLogger.logger.info("clear stackRuleMaps");
        stackRuleMaps.clear();
        ruleLock.writeLock().unlock();
    }
}
