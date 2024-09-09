package com.security.smith.ruleengine;



import javax.script.*;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import com.security.smith.common.RSAUtil;

import com.security.smith.log.*;
import jdk.nashorn.api.scripting.NashornScriptEngineFactory;

public class JsExecutor {
    public static final int COMMON_TYPE = 1;
    public static final int REFLECT_TYPE  = 2;
    public static final int MAX_TYPE = 2;
    private static String LANGUAGE_ES6 = "--language=es6";
    private NashornScriptEngineFactory jsEngineFactory;
    private ScriptEngine jsEngine;
    private ScriptContext jsctx;
    private Invocable inv;
    private int ruletype = -1;
    private int ruleid = -1;
    private int rulever;
    private String rulename;
    private int enginever;
    private int argsNum;
    private boolean bInited = false;

    public static void InitInstance() {

    }

    public static void UninitInstance() {

    }

    public boolean InitJsRule() {
        boolean bret = false;

        /*

            init js rule

        */
        try {
            bret = (boolean)inv.invokeFunction("initialize");
            if(bret) {
                bret = false;
                bInited = true;
                rulever= (int)inv.invokeFunction("get_rule_version");
                enginever = (int)inv.invokeFunction("rule_engine_version");
                bret = true;
            }
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }

        if(!bret) {
            if(bInited) {
                try {
                    inv.invokeFunction("uninitialize");
                }
                catch(Exception e) {
                    SmithLogger.exception(e);
                }

                bInited = false;
            }

            rulever = -1;
            enginever = -1;
        }

        return bret;
    }

    private boolean UnInitJsRule() {
        boolean bret = false;

        if(bInited) {
            bInited = false;

            try {
                bret = (boolean)inv.invokeFunction("uninitialize");
            } catch(Exception e) {
                SmithLogger.exception(e);
            }
        }

        return bret;
    }

    public JsExecutor() {
        jsctx = null;
        jsEngine = null;
        jsEngineFactory = null;
        ruletype = 0xFFFFFFFF;
        ruleid = 0xFFFFFFFF;
        rulename = null;
        enginever = 0xFFFFFFFF;
        argsNum = 0xFFFFFFFF;
    }

    private byte[] parseScript(String script) {
        try {
            byte[] encryptedData = Files.readAllBytes(Paths.get(script));
            return RSAUtil.decryptRSA(encryptedData);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
        return null;
    }

    public boolean Initialize(NashornScriptEngineFactory EngineFactory,JsRuleInterfaceMgr jsInterfaceMgr,Path ScriptFilePath) {
        boolean     bret = false;

        /*
        *
        *  load script
        *
        * */
        try {
            Path filename = ScriptFilePath.getFileName();

            rulename = filename.toString();

            jsEngineFactory = EngineFactory;
            jsEngine = EngineFactory.getScriptEngine(LANGUAGE_ES6); 

            jsEngine.put("JsRuleInterfaceMgr",jsInterfaceMgr);
            byte[] script = parseScript(ScriptFilePath.toString());
            if (script == null) {
                SmithLogger.logger.info("load script failed");
                return false;
            }

            jsEngine.eval(new String(script));

            inv = (Invocable)jsEngine;

            bret = true;
        } catch(Throwable e) {
            bret = false;

            jsctx = null;
            jsEngineFactory = null;
            jsEngine = null;
            inv = null;
            SmithLogger.exception(e);
        }

        return bret;
    }

    public boolean Uninitialize() {
        boolean bret = false;

        bret = UnInitJsRule();

        jsctx = null;
        jsEngine = null;
        jsEngineFactory = null;
        inv = null;
        rulename = null;
        ruletype = -1;
        ruleid = -1;
        rulever = -1;

        return bret;
    }

    public boolean detect(Object[] args) {
        boolean bret = false;

        if(!bInited) {
            return false;
        }
        // SmithLogger.logger.info("JsExecutor.detect, args num: "+ argsNum);

       if(args.length == argsNum) {
           try {
               switch(argsNum) {
                   case 0: {
                       bret = (boolean)inv.invokeFunction("detect");
                   }
                   break;
                   case 1: {
                       bret = (boolean)inv.invokeFunction("detect", args[0]);
                   }
                   break;
                   case 2: {
                       bret = (boolean)inv.invokeFunction("detect", args[0],args[1]);
                   }
                   break;
                   case 3: {
                       bret = (boolean)inv.invokeFunction("detect", args[0],args[1],args[2]);
                   }
                   break;
                   case 4: {
                       bret = (boolean)inv.invokeFunction("detect", args[0],args[1],args[2],args[3]);
                   }
                   break;
                   default: {
                       bret = false;
                   }
               }
           } catch(Exception e) {
               SmithLogger.exception(e);
           }

           return bret;
       }

       SmithLogger.logger.info("JsExecutor.detect args num invalid,need "+ argsNum + " Current "+args.length);
       return false;
    }

    public int getRuleType() {
        if(ruletype != -1) {
            return ruletype;
        }

        try {
            ruletype = (int)inv.invokeFunction("get_rule_type");
            switch(ruletype) {
                case COMMON_TYPE: {
                    argsNum = 2;
                }
                break;
                case REFLECT_TYPE: {
                    argsNum = 3;
                }
                break;
                default: {
                    ruletype = -1;
                }
            }
        }
        catch (Exception e) {
            SmithLogger.exception(e);
            ruletype = -1;
        }

        return ruletype;
    }

    public int getRuleId() {
       if(ruleid != -1)  {
           return ruleid;
       }

       try {
           ruleid = (int)inv.invokeFunction("get_rule_id");
       }
       catch (Exception e) {
           SmithLogger.exception(e);
           ruleid = -1;
       }

       return ruleid;
    }

    public int getRuleVer() {
        return rulever;
    }

    public String getRuleName() {
        return rulename;
    }

    public int getEnginever() {
        return enginever;
    }
}
