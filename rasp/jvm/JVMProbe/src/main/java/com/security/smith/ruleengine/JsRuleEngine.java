package com.security.smith.ruleengine;

import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import com.security.smith.log.*;
import jdk.nashorn.api.scripting.NashornScriptEngineFactory;

public class JsRuleEngine {
    private static boolean  bInited = false;
    private static AtomicInteger  enterCount = null;
    private static JsRuleEngine instance = null;
    private static JsRuleInterfaceMgr jsInterfaceMgr = null;
    private static StackRuleMgr stackRuleMgr = null;
    private static NashornScriptEngineFactory engineFactory = null;
    private static Map<Integer,JsExecutor>[] jsExecuterMgr = null;
    private static ReadWriteLock jsExecuterMgrLock = null;

    private synchronized static void _InitializeEngine_() {
        try {
            enterCount = new AtomicInteger(0);
            instance = new JsRuleEngine();
            jsExecuterMgrLock = new ReentrantReadWriteLock();
            jsExecuterMgr = new ConcurrentHashMap[3];
            jsExecuterMgr[0] = null;
            jsExecuterMgr[1] = new ConcurrentHashMap<>();
            jsExecuterMgr[2] = new ConcurrentHashMap<>();
            stackRuleMgr = new StackRuleMgr();
            stackRuleMgr.Initialize();

            jsInterfaceMgr = new JsRuleInterfaceMgr(stackRuleMgr);
            //jsInterfaceMgr.setStackRuleMgr(stackRuleMgr);
            engineFactory = new NashornScriptEngineFactory();
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        
    }

    public  static JsRuleEngine InitializeEngine() {
        if (instance != null) {
            return instance;
        }

        _InitializeEngine_();

        bInited = true;

        return instance;
    }

    public synchronized static boolean UninitializeEngine() {
        if(!bInited) {
            return true;
        }

        bInited = false;

        while(enterCount.get() != 0) {
            try {
                Thread.sleep(100);
            }
            catch(Exception e) {

            }
        }

        instance = null;

        try {
            jsExecuterMgrLock.writeLock().lock();

            for(int i = 0;i < jsExecuterMgr.length;i++) {

                if(jsExecuterMgr[i] != null) {
                    Map<Integer,JsExecutor> Map = jsExecuterMgr[i];
                    //  uninit all js executer
                    for (Map.Entry<Integer,JsExecutor> entry : Map.entrySet()) {
                        try {
                            JsExecutor  Executer = entry.getValue();
                            Executer.Uninitialize();
                        }
                        catch(Exception e) {
                            SmithLogger.exception(e);
                        }
                    }

                    jsExecuterMgr[i] = null;
                }
            }

            jsExecuterMgr = null;
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }
        finally {
            jsExecuterMgrLock.writeLock().unlock();
        }

        jsInterfaceMgr = null;
        stackRuleMgr.Uninitialize();
        stackRuleMgr = null;
        jsExecuterMgrLock = null;
        engineFactory = null;
        enterCount = null;

        return true;
    }

    public  int addJsRule(Path ScriptFilePath) {
        int ret = -1;
        JsExecutor  jsExecuter = null;

        if(!bInited) {
            return 2;
        }

        enterCount.incrementAndGet();

        jsExecuter = new JsExecutor();
        if(!jsExecuter.Initialize(jsInterfaceMgr,ScriptFilePath)) {
            enterCount.decrementAndGet();
            return 4;
        }

        int ruletype = jsExecuter.getRuleType();
        if(ruletype >= JsExecutor.MAX_TYPE ||
                ruletype <= 0) {
            jsExecuter.Uninitialize();

            enterCount.decrementAndGet();

            return 5;
        }

        int ruleid = jsExecuter.getRuleId();

        try {
            jsExecuterMgrLock.readLock().lock();

            if(jsExecuterMgr[ruletype].containsKey(ruleid)) {
                ret = 0xFF;
            }
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }
        finally {
            jsExecuterMgrLock.readLock().unlock();
        }

        if(ret == 0xFF) {
            jsExecuter.Uninitialize();
            enterCount.decrementAndGet();
            return ret;
        }

        try {
            jsExecuterMgrLock.writeLock().lock();

            ret = 6;
            jsExecuterMgr[ruletype].put(ruleid,jsExecuter);
            ret = 0;
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }
        finally {
            jsExecuterMgrLock.writeLock().unlock();
        }

        if(ret == 0) {
            if(!jsExecuter.InitJsRule()) {
                jsExecuter.Uninitialize();
                ret = 7;
            }
        }
        else {
            jsExecuter.Uninitialize();
        }

        enterCount.decrementAndGet();

        return ret;
    }

    public JsRuleResult detect(int ruletype,Object args[]) {
        JsRuleResult ret = null;
        boolean     bInitStack = false;

        if(!bInited) {
            return null;
        }

        enterCount.incrementAndGet();

        if(ruletype >= JsExecutor.MAX_TYPE ||
            ruletype <= 0) {
            enterCount.decrementAndGet();
            return null;
        }

        try {
            bInitStack = stackRuleMgr.InitCallStack(ruletype);

            jsExecuterMgrLock.readLock().lock();

            Map<Integer,JsExecutor> Map = jsExecuterMgr[ruletype];
            //  enum all js executer
            for (Map.Entry<Integer,JsExecutor> entry : Map.entrySet()) {
                SmithLogger.logger.info("ruleid = " + entry.getKey());


                JsExecutor  Executer = entry.getValue();
                if(Executer.detect(args)) {
                    ret = new JsRuleResult();
                    ret.ruletype = ruletype;
                    ret.ruleid = entry.getKey();
                    ret.rulever = Executer.getRuleVer();
                    ret.rulename = Executer.getRuleName();
                    break;
                }
            }
        }
        catch(Exception e) {
           SmithLogger.exception(e);
        }
        finally {
            jsExecuterMgrLock.readLock().unlock();

            if (bInitStack) {
                stackRuleMgr.UninitCallStack(ruletype);
            }
        }

        enterCount.decrementAndGet();

        return ret;
    }
}
