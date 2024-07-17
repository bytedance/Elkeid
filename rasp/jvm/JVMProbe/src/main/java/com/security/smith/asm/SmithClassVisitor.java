package com.security.smith.asm;

import com.security.smith.type.SmithMethod;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

import java.util.Map;

public class SmithClassVisitor extends ClassVisitor {
    private final int classID;
    private final Type classType;
    private final Map<String, SmithMethod> methodMap;

    public SmithClassVisitor(int api, ClassVisitor classVisitor, int classID, Type classType, Map<String, SmithMethod> methodMap) {
        super(api, classVisitor);

        this.classID = classID;
        this.classType = classType;
        this.methodMap = methodMap;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);

        SmithMethod smithMethod = null;
        if (name.equals("<init>")) {
            smithMethod = methodMap.get(name);
            if (smithMethod == null) {
                smithMethod = methodMap.get(name + descriptor);
            }
        } else {
            smithMethod = methodMap.get(name + descriptor);
        }
        

        if (smithMethod == null)
            return methodVisitor;

        return new SmithMethodVisitor(this.api,classType, classID, smithMethod.getId(), smithMethod.isBlock(), methodVisitor, access, name, descriptor, smithMethod.getPreHook(), smithMethod.getPostHook(), smithMethod.getExceptionHook());
    }
}
