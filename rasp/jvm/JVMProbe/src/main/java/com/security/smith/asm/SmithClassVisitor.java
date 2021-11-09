package com.security.smith.asm;

import com.security.smith.type.SmithMethod;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

import java.util.Map;

public class SmithClassVisitor extends ClassVisitor {
    public SmithClassVisitor(int api, ClassVisitor classVisitor, int classID, String className, Map<String, SmithMethod> methodMap) {
        super(api, classVisitor);

        this.classID = classID;
        this.className = className;
        this.methodMap = methodMap;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);

        SmithMethod smithMethod = methodMap.get(name + descriptor);

        if (smithMethod == null)
            return methodVisitor;

        return new SmithMethodVisitor(this.api, className, classID, smithMethod.getId(), smithMethod.isBlock(), methodVisitor, access, name, descriptor);
    }

    private final int classID;
    private final String className;
    private final Map<String, SmithMethod> methodMap;
}
