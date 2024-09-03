package com.security.smith.ruleengine;

import com.security.smith.rulemgr.*;

import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import com.security.smith.log.*;

public class StackRuleMgr {
    private static boolean  bInited = false;
    private static StackRuleManager[] ruleMgr = null;
    private static ReadWriteLock ruleMgrLock = null;

    public synchronized static boolean Initialize() {
        boolean bret = false;

        if(bInited) {
            return true;
        }

        bInited = true;


        try {
            ruleMgrLock = new ReentrantReadWriteLock();
            ruleMgr = new StackRuleManager[3];
            ruleMgr[0] = null;
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        return bret;
    }

    public synchronized static boolean Uninitialize() {
        boolean bret = false;

        if(!bInited) {
            return true;
        }

        bInited = false;

        try {
            ruleMgrLock.writeLock().lock();

            for(int i = 0;i < ruleMgr.length;i++) {
                if(ruleMgr[i] != null) {
                    StackRuleManager ruleX = ruleMgr[i];

                    ruleX.clear();

                    ruleMgr[i] = null;
                }
            }

            ruleMgr = null;
        }
        catch (Exception e) {
            SmithLogger.exception(e);
        }
        finally {
            ruleMgrLock.writeLock().unlock();
        }

        ruleMgrLock = null;

        return bret;
    }

   private static StackRuleManager get_StackRuleManager(int ruletype) {
       StackRuleManager ret = null;

       try {
           ruleMgrLock.readLock().lock();

           ret = ruleMgr[ruletype];
       }
       catch (Exception e) {
           SmithLogger.exception(e);
       }
       finally {
           ruleMgrLock.readLock().unlock();
       }

       return ret;
   }

    public static boolean add_white_stack_rule(int ruletype,int ruleid,String[] rule) {
        boolean bret = false;
        boolean block = false;

        if(!bInited) {
            return false;
        }

        if(ruletype >= JsExecutor.MAX_TYPE ||
                ruletype <= 0) {
            return false;
        }

        try {
            if(ruleMgr[ruletype] == null) {
                ruleMgrLock.writeLock().lock();
                block = true;

                if (ruleMgr[ruletype] == null) {
                    ruleMgr[ruletype] = new StackRuleManager();
                }
            }
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }
        finally {
            if(block) {
                ruleMgrLock.writeLock().unlock();
            }
        }

        try {
            StackRuleManager ruleX = get_StackRuleManager(ruletype);
            bret = ruleX.addWhiteStackRule(ruleid,rule);
        }
        catch (Exception e) {
            SmithLogger.exception(e);
        }

        return bret;
    }

    public static boolean add_black_stack_rule(int ruletype,int ruleid,String[] rule) {
        boolean bret = false;
        boolean block = false;

        if(!bInited) {
            return false;
        }

        if(ruletype >= JsExecutor.MAX_TYPE ||
                ruletype <= 0) {
            return false;
        }

        try {
            if(ruleMgr[ruletype] == null) {
                ruleMgrLock.writeLock().lock();
                block = true;

                if (ruleMgr[ruletype] == null) {
                    ruleMgr[ruletype] = new StackRuleManager();
                }
            }
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }
        finally {
            if(block) {
                ruleMgrLock.writeLock().unlock();
            }
        }

        try {
            StackRuleManager ruleX = get_StackRuleManager(ruletype);
            bret = ruleX.addBlackStackRule(ruleid,rule);
        }
        catch (Exception e) {
            SmithLogger.exception(e);
        }

        return bret;
    }

    public static boolean del_white_stack_rule(int ruletype,int ruleid) {
        boolean bret = false;

        if(!bInited) {
            return true;
        }

        if(ruletype >= JsExecutor.MAX_TYPE ||
                ruletype <= 0) {
            return false;
        }

        try {
            StackRuleManager ruleX = get_StackRuleManager(ruletype);
            if(ruleX != null) {
                bret = ruleX.removeWhiteStackRule(ruleid);
            }
            else {
                bret = true;
            }
        }
        catch (Exception e) {
            SmithLogger.exception(e);
        }

        return bret;
    }

    public static boolean del_black_stack_rule(int ruletype,int ruleid) {
        boolean bret = false;

        if(!bInited) {
            return true;
        }

        if(ruletype >= JsExecutor.MAX_TYPE ||
                ruletype <= 0) {
            return false;
        }

        try {
            StackRuleManager ruleX = get_StackRuleManager(ruletype);
            if(ruleX != null) {
                bret = ruleX.removeBlackStackRule(ruleid);
            }
            else {
                bret = true;
            }
        }
        catch (Exception e) {
            SmithLogger.exception(e);
        }

        return bret;
    }

    public static boolean white_stack_detect(int ruletype,int ruleid) {
        boolean bret = false;

        if(!bInited) {
            return false;
        }

        if(ruletype >= JsExecutor.MAX_TYPE ||
                ruletype <= 0) {
            return false;
        }

        try {
            StackRuleManager ruleX = get_StackRuleManager(ruletype);
            if(ruleX != null) {
                bret = ruleX.isMatched(ruleid,true);
            }
        }
        catch (Exception e) {
            SmithLogger.exception(e);
        }

        return bret;
    }

    public static boolean black_stack_detect(int ruletype,int ruleid) {
        boolean bret = false;

        if(!bInited) {
            return false;
        }

        if(ruletype >= JsExecutor.MAX_TYPE ||
                ruletype <= 0) {
            return false;
        }

        try {
            StackRuleManager ruleX = get_StackRuleManager(ruletype);
            if(ruleX != null) {
                bret = ruleX.isMatched(ruleid,false);
            }
        }
        catch (Exception e) {
            SmithLogger.exception(e);
        }

        return bret;
    }

    public static boolean InitCallStack(int ruletype) {
        boolean bret = false;

        if(!bInited) {
            return false;
        }

        if(ruletype >= JsExecutor.MAX_TYPE ||
                ruletype <= 0) {
            return false;
        }

        try {
            StackRuleManager ruleX = get_StackRuleManager(ruletype);
            if(ruleX != null) {
                 ruleX.formatStack();
                 bret = true;
            }
        }
        catch (Exception e) {
            SmithLogger.exception(e);
        }

        return bret;
    }

    public static void UninitCallStack(int ruletype) {
        if(!bInited) {
            return ;
        }

        if(ruletype >= JsExecutor.MAX_TYPE ||
                ruletype <= 0) {
            return ;
        }

        try {
            StackRuleManager ruleX = get_StackRuleManager(ruletype);
            if(ruleX != null) {
                ruleX.clearStack();
            }
        }
        catch (Exception e) {
            SmithLogger.exception(e);
        }
    }
}
