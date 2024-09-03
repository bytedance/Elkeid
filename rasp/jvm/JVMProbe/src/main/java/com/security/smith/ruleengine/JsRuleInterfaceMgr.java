package com.security.smith.ruleengine;


// import jdk.nashorn.api.scripting.ScriptObjectMirror;
import jdk.nashorn.internal.objects.NativeArray;
import com.security.smith.log.*;
import java.util.ArrayList;
import java.util.List;

public class JsRuleInterfaceMgr {
    private final StackRuleMgr stackRuleMgr;

    public JsRuleInterfaceMgr(StackRuleMgr rulemgr) {
       stackRuleMgr = rulemgr;
    }

    /*
    public static void setStackRuleMgr(StackRuleMgr rulemgr) {
        stackRuleMgr = rulemgr;
    }

     */

    public Object java_callback(int functionID, Object[] args) {
        switch (functionID) {
            case 1:
                return (Object)add_white_stack_rule_proxy(args);
            case 2:
                return (Object)add_black_stack_rule_proxy(args);
            case 3:
                return (Object)white_stack_detect_proxy(args);
            case 4:
                return (Object)black_stack_detect_proxy(args);
            case 5:
                return (Object)del_white_stack_rule_proxy(args);
            case 6:
                return (Object)del_black_stack_rule_proxy(args);
            default:
                return null;
        }
    }

    private String[] Convert_JsStringArray_To_JavaStringArray(Object jsArray) {
        if (jsArray  instanceof jdk.nashorn.internal.objects.NativeArray) {
        try {
            jdk.nashorn.internal.objects.NativeArray array = (jdk.nashorn.internal.objects.NativeArray)jsArray;

            List<String> javaList = new ArrayList<>();
            for (Object obj : array.values()) {
                javaList.add(obj.toString());
            }

            return javaList.toArray(new String[javaList.size()]);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }
               
        // } else if (jsArray instanceof NativeArray) {
        //     NativeArray array = (NativeArray)jsArray;
        //     String[] javaArray = new String[array.getLength()];
        //     for (int i = 0; i < array.getLength(); i++) {
        //         javaArray[i] = array.get(i).toString();
        //     }
        //     return javaArray;
        }

        return null;
    }

    private boolean add_white_stack_rule_proxy(Object[] args) {
        int ruletype = (int)args[0];
        int ruleid = (int)args[1];
        String[] rule = Convert_JsStringArray_To_JavaStringArray(args[2]);

        if(rule == null) {
            return false;
        }

        return stackRuleMgr.add_white_stack_rule(ruletype,ruleid,rule);
    }

    private boolean  add_black_stack_rule_proxy(Object[] args) {
        int ruletype = (int)args[0];
        int ruleid = (int)args[1];
        String[] rule = Convert_JsStringArray_To_JavaStringArray(args[2]);


        if(rule == null) {
            return false;
        }

        return stackRuleMgr.add_black_stack_rule(ruletype,ruleid,rule);
    }

    private boolean del_white_stack_rule_proxy(Object[] args) {
        int ruletype = (int)args[0];
        int ruleid = (int)args[1];

        return stackRuleMgr.del_white_stack_rule(ruletype,ruleid);
    }

    private boolean del_black_stack_rule_proxy(Object[] args) {
        int ruletype = (int)args[0];
        int ruleid = (int)args[1];

        return stackRuleMgr.del_black_stack_rule(ruletype,ruleid);
    }

    private boolean white_stack_detect_proxy(Object[] args) {
        int ruletype = (int)args[0];
        int ruleid = (int)args[1];

        return stackRuleMgr.white_stack_detect(ruletype,ruleid);
    }

    private boolean black_stack_detect_proxy(Object[] args) {
        int ruletype = (int)args[0];
        int ruleid = (int)args[1];

        return stackRuleMgr.black_stack_detect(ruletype,ruleid);
    }
}
