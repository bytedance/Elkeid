package com.security.smith.rulemgr;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import net.jpountz.xxhash.XXHash32;
import net.jpountz.xxhash.XXHash64;
import net.jpountz.xxhash.XXHashFactory;

import com.security.smith.common.Reflection;
import com.security.smith.log.SmithLogger;

public class StackRuleManager {
    public  Map<Integer, StackRule> stackRuleMaps = new ConcurrentHashMap<>();
    private XXHashFactory factory = XXHashFactory.fastestInstance();
    private XXHash64 hash64 = factory.hash64();
    private long seed64 = 0x9747b28c727a1617L;

    public ThreadLocal<Map<Long, String>>  currentStack = new ThreadLocal<Map<Long, String>>() {
        @Override
        protected  Map<Long, String> initialValue() {
            return new HashMap<>();
        }
    };

    public ThreadLocal<Boolean> stackSwitch = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return true;
        }
    };


    public boolean addBlackStackRule(Integer ruleId, String[] stackinfo) {
        if (stackSwitch == null || stackSwitch.get() == false) {
            return false;
        }
        if (ruleId == null ||stackinfo == null || stackinfo.length == 0) {
            return false;
        }
        StackRule stackRule = null;
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

        try {
            stackRule.setBlackItems(items);
            stackRuleMaps.put(stackRule.getRuleId(), stackRule);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    
        SmithLogger.logger.info("add black stack rule: " + stackRule.getRuleId());
        return true;
    }

    public boolean addWhiteStackRule(Integer ruleId, String[] stackinfo) {
        if (stackSwitch == null || stackSwitch.get() == false) {
            return false;
        }
        if (ruleId == null ||stackinfo == null || stackinfo.length == 0) {
            return false;
        }
        StackRule stackRule = null;
        try {
            if (stackRuleMaps.containsKey(ruleId)) {
                stackRule = stackRuleMaps.get(ruleId);
            } else {
                stackRule = new StackRule();
                stackRule.setRuleId(ruleId);
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
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

        try {
            stackRule.setWhiteItems(items);
            stackRuleMaps.put(stackRule.getRuleId(), stackRule);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        
        return true;
    }

    public boolean removeBlackStackRule(Integer ruleId) {
        if (stackSwitch == null || stackSwitch.get() == false) {
            return false;
        }
        boolean ret = false;
        try {
            if (stackRuleMaps.containsKey(ruleId)) {
                StackRule stackRule = stackRuleMaps.get(ruleId);
                stackRule.removeBlackStackRule();
                ret = true;
    
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        
        return ret;
    }

    public boolean removeWhiteStackRule(Integer ruleId) {
        if (stackSwitch == null || stackSwitch.get() == false) {
            return false;
        }
        boolean ret = false;

        try {
            if (stackRuleMaps.containsKey(ruleId)) {
                StackRule stackRule = stackRuleMaps.get(ruleId);
                stackRule.removeWhiteStackRule();
                ret = true;
            }
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    
        return ret;
    }

    public StackRule getStackRule(Integer ruleId) {
        StackRule stackRule = null;

        try {
            stackRule = stackRuleMaps.get(ruleId);
        } catch (Exception e) {
            SmithLogger.exception(e);
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
        if (stackSwitch == null || stackSwitch.get() == false) {
            return false;
        }
        if (ruleId == null || !stackRuleMaps.containsKey(ruleId)) {
            SmithLogger.logger.info("ruleId is null or stackinfo is null or ruleId is not exist");
            return false;
        }
    
        try {
            boolean needClearStack = false;
            if (currentStack == null || currentStack.get().isEmpty()) {
                needClearStack = true;
                formatStack();
            }
            SmithLogger.logger.info("isWhite: " + isWhite + " ruleId: " + ruleId);

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
                        Map<Long, String> curStack = currentStack.get();
                        for (StackItem item : items) {
                            if (item != null && curStack != null && !curStack.isEmpty()) {
                                if (item.getHashcode() == 0) {
                                    String stack = item.getStackinfo();
                                    try {
                                        for (Map.Entry<Long, String> entry : curStack.entrySet()) {
                                            String value = entry.getValue();
                                            if (value.contains(stack.substring(0, stack.length() - 1))) {
                                                SmithLogger.logger.info("find the match, string: " + value + " hashcode: " + entry.getKey());
                                                return true;
                                            }
                                        }
                                    } catch (Exception e) {
                                        SmithLogger.exception(e);
                                    }
                                    
                                } else {
                                    try {
                                        if (curStack.containsKey(item.getHashcode())) {
                                            SmithLogger.logger.info("find the match, string: " + curStack.get(item.getHashcode()) + " hashcode: " + item.getHashcode());
                                            return true;
                                        }
                                    } catch (Exception e) {
                                        SmithLogger.exception(e);
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                SmithLogger.exception(e);
            } finally {
                if (needClearStack) {
                    currentStack.get().clear();
                }
            }
            
            SmithLogger.logger.info("not find the match");
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        return false;
    }

    public void formatStack() {
        if (stackSwitch == null || stackSwitch.get() == false) {
            return ;
        }
        try {
            Map<Long, String> cur1Stack = currentStack.get();
            SmithLogger.logger.info("curStack size: " + cur1Stack.size());
            SmithLogger.logger.info("now to get current stack");
            StackTraceElement[] stack_str  =  Thread.currentThread().getStackTrace();
            String[] stackTraceStrings = new String[stack_str.length];
            Map<Long, String> curStack = new HashMap<>();

            for (int i = 0; i < stack_str.length; i++) {
                stackTraceStrings[i] = stack_str[i].toString();
                if (stackTraceStrings[i] != null && !stackTraceStrings[i].isEmpty()) {
                    String stack = stackTraceStrings[i].replaceAll("\\(.*\\)", "");
                    byte[] data = stack.getBytes(StandardCharsets.UTF_8);
                    curStack.put(hash64.hash(data, 0, data.length, seed64), stackTraceStrings[i]);
                }
            }
            currentStack.set(curStack);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        return ;
    }

    public void clearStack() {
        if (stackSwitch == null || stackSwitch.get() == false) {
            return ;
        }
        try {
            Map<Long, String> curStack = currentStack.get();
            SmithLogger.logger.info("curStack size: " + curStack.size());
            curStack.clear();
            SmithLogger.logger.info("clear currentStack");
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }

    private boolean removeThreadLocalFormThread(Object threadObj,Object threadLocalObj) {
        boolean bret = false;
        boolean usegetMap = false;

        if (threadObj == null ||
           threadLocalObj == null)  {
            return false;
        }

        try {
            String className = threadLocalObj.getClass().getSuperclass().getName();
            if(className.contains("java.lang.InheritableThreadLocal")) {
                Class<?>[]  argType_remove = new Class[]{Thread.class};
                 bret = Reflection.invokeSuperSuperMethodNoReturn(threadLocalObj,"remove",argType_remove,threadObj);
            }
            else if(className.contains("java.lang.ThreadLocal")) {
                Class<?>[]  argType_remove = new Class[]{Thread.class};
                bret = Reflection.invokeSuperMethodNoReturn(threadLocalObj,"remove",argType_remove,threadObj);
            }
        }
        catch(Throwable t) {
        }

        if(!bret) {
            try {
                Class<?>[]  argType_getMap = new Class[]{Thread.class};
                Object threadlocalMap = Reflection.invokeSuperMethod(threadLocalObj,"getMap",argType_getMap,threadObj);
                if(threadlocalMap != null) {
                    Class<?>[]  argType_remove = new Class[]{ThreadLocal.class};
                    bret = Reflection.invokeMethodNoReturn(threadlocalMap,"remove",argType_remove,threadLocalObj);

                }
            }
            catch(Throwable t) {
                SmithLogger.exception(t);
            }
        }

        return bret;
    }

    private void RemoveThreadLocalVar() {
        int activeCount = Thread.activeCount();
        Thread[] threads = new Thread[activeCount+100];
        int count = Thread.enumerate(threads);
        for (int i = 0; i < count; i++) {
            removeThreadLocalFormThread(threads[i], currentStack);
            removeThreadLocalFormThread(threads[i], stackSwitch);
        }
    }

    public void clear() {
        if (stackSwitch == null || stackSwitch.get() == false) {
            return ;
        }
        stackSwitch.set(false);
        stackSwitch.remove();
        stackSwitch = null;
        try {
            for (StackRule stackRule : stackRuleMaps.values()) {
                stackRule.removeBlackStackRule();
                stackRule.removeWhiteStackRule();
            }
            SmithLogger.logger.info("clear stackRuleMaps");
            stackRuleMaps.clear();
            stackRuleMaps = null;
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        try {
            clearStack();
            currentStack.remove();
            currentStack = null;
            // RemoveThreadLocalVar();
            factory = null;
            hash64 = null;
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
    }
}
