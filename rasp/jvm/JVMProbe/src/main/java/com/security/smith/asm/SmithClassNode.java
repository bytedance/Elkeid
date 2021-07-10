package com.security.smith.asm;

import com.security.smith.log.SmithLogger;
import com.security.smith.type.SmithMethod;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;

import java.util.Map;

public class SmithClassNode extends ClassNode {
    public SmithClassNode(int api) {
        super(api);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        SmithMethod smithMethod = methodMap.get(name + descriptor);

        if (smithMethod == null)
            return super.visitMethod(access, name, descriptor, signature, exceptions);

        SmithMethodNode method;

        if (smithMethod.isRet() && Type.getReturnType(descriptor) != Type.VOID_TYPE) {
            SmithLogger.logger.info(String.format("ret probe: %s.%s%s", this.name, name, descriptor));
            method = new SmithRetProbeNode(api, access, name, descriptor, signature, exceptions);
        } else {
            SmithLogger.logger.info(String.format("probe: %s.%s%s", this.name, name, descriptor));
            method = new SmithProbeNode(api, access, name, descriptor, signature, exceptions);
        }

        method.setClassID(classID);
        method.setMethodID(smithMethod.getId());
        method.setClassName(this.name);
        method.setProbeName(probeName.replace(".", "/"));

        methods.add(method);

        return method;
    }

    public void setClassID(int classID) {
        this.classID = classID;
    }

    public void setMethodMap(Map<String, SmithMethod> methodMap) {
        this.methodMap = methodMap;
    }

    public void setProbeName(String probeName) {
        this.probeName = probeName;
    }

    private int classID;
    private String probeName;
    private Map<String, SmithMethod> methodMap;
}
