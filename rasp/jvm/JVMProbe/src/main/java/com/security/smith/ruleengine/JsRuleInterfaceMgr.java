package com.security.smith.ruleengine;

// import org.openjdk.nashorn.api.scripting.ScriptObjectMirror;
// import org.openjdk.nashorn.internal.objects.NativeArray;
import jdk.nashorn.api.scripting.ScriptObjectMirror;
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
        // 检查结果是否为ScriptObjectMirror
        if (jsArray  instanceof jdk.nashorn.api.scripting.ScriptObjectMirror) {
                jdk.nashorn.api.scripting.ScriptObjectMirror array = (jdk.nashorn.api.scripting.ScriptObjectMirror)jsArray;

                // 将JavaScript数组转换为Java List
                List<String> javaList = new ArrayList<>();
                for (Object obj : array.values()) {
                    javaList.add(obj.toString());
                }

                return javaList.toArray(new String[javaList.size()]);
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
