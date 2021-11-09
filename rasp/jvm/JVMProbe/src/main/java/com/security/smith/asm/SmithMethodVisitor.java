package com.security.smith.asm;

import com.security.smith.SmithProbe;
import com.security.smith.process.*;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

import java.util.HashMap;
import java.util.Map;

public class SmithMethodVisitor extends AdviceAdapter {
    private static final Map<String, Class<?>> smithProcesses = new HashMap<String, Class<?>>() {{
        put("byte[]", ByteArrayProcess.class);
        put("int[]", IntegerArrayProcess.class);
        put("java.net.ProtocolFamily", ProtocolFamilyProcess.class);
        put("java.io.FileDescriptor", FileDescriptorProcess.class);
        put("java.net.URL[]", ObjectArrayProcess.class);
        put("java.net.DatagramPacket", DatagramPacketProcess.class);
        put("java.net.DatagramSocket", DatagramSocketProcess.class);
        put("java.lang.String[]", ObjectArrayProcess.class);
        put("java.lang.Process", ProcessProcess.class);
        put("java.lang.UNIXProcess", ProcessProcess.class);
        put("java.lang.ProcessImpl", ProcessProcess.class);
        put("java.net.InetAddress[]", ObjectArrayProcess.class);
    }};

    protected SmithMethodVisitor(int api, String className, int classID, int methodID, boolean canBlock, MethodVisitor methodVisitor, int access, String name, String descriptor) {
        super(api, methodVisitor, access, name, descriptor);

        this.className = className;
        this.classID = classID;
        this.methodID = methodID;
        this.canBlock = canBlock;

        start = new Label();
        end = new Label();
        handler = new Label();

        argumentsVariable = newLocal(Type.getType(Object[].class));
        returnVariable = newLocal(Type.getType(Object.class));

        isConstructor = name.equals("<init>");
        isStatic = (access & Opcodes.ACC_STATIC) != 0;
    }

    @Override
    public void loadArgArray() {
        int reserved = isStatic || isConstructor ? 0 : 1;
        Type[] argumentTypes = Type.getArgumentTypes(methodDesc);

        push(argumentTypes.length + reserved);
        newArray(Type.getType(Object.class));

        if (reserved > 0) {
            dup();
            push(0);
            loadThis();
            processObject(className);
            arrayStore(Type.getType(Object.class));
        }

        for (int i = 0; i < argumentTypes.length; i++) {
            dup();
            push(i + reserved);
            loadArg(i);
            box(argumentTypes[i]);
            processObject(argumentTypes[i].getClassName());
            arrayStore(Type.getType(Object.class));
        }
    }

    @Override
    protected void onMethodEnter() {
        super.onMethodEnter();

        visitTryCatchBlock(start, end, handler, Type.getInternalName(Exception.class));

        loadArgArray();
        storeLocal(argumentsVariable);

        mark(start);

        if (!canBlock)
            return;

        invokeStatic(
                Type.getType(SmithProbe.class),
                new Method(
                        "getInstance",
                        Type.getType(SmithProbe.class),
                        new Type[]{}
                )
        );

        push(classID);
        push(methodID);
        loadLocal(argumentsVariable);

        invokeVirtual(
                Type.getType(SmithProbe.class),
                new Method(
                        "detect",
                        Type.VOID_TYPE,
                        new Type[]{
                                Type.INT_TYPE,
                                Type.INT_TYPE,
                                Type.getType(Object[].class)
                        }
                )
        );
    }

    @Override
    protected void onMethodExit(int opcode) {
        super.onMethodExit(opcode);

        if (opcode == ATHROW)
            return;

        Type returnType = Type.getReturnType(methodDesc);

        if (opcode == RETURN) {
            if (isConstructor) {
                loadThis();
                processObject(className);
            } else {
                visitInsn(ACONST_NULL);
            }
        } else if (opcode == ARETURN) {
            dup();
            processObject(returnType.getClassName());
        } else {
            if (opcode == LRETURN || opcode == DRETURN) {
                dup2();
            } else {
                dup();
            }

            box(returnType);
        }

        storeLocal(returnVariable);

        invokeStatic(
                Type.getType(SmithProbe.class),
                new Method(
                        "getInstance",
                        Type.getType(SmithProbe.class),
                        new Type[]{}
                )
        );

        push(classID);
        push(methodID);
        loadLocal(argumentsVariable);
        loadLocal(returnVariable);

        invokeVirtual(
                Type.getType(SmithProbe.class),
                new Method(
                        "trace",
                        Type.VOID_TYPE,
                        new Type[]{
                                Type.INT_TYPE,
                                Type.INT_TYPE,
                                Type.getType(Object[].class),
                                Type.getType(Object.class)
                        }
                )
        );
    }

    @Override
    public void visitEnd() {
        super.visitEnd();

        mark(end);
        mark(handler);

        invokeStatic(
                Type.getType(SmithProbe.class),
                new Method(
                        "getInstance",
                        Type.getType(SmithProbe.class),
                        new Type[]{}
                )
        );

        push(classID);
        push(methodID);
        loadLocal(argumentsVariable);
        visitInsn(Opcodes.ACONST_NULL);

        invokeVirtual(
                Type.getType(SmithProbe.class),
                new Method(
                        "trace",
                        Type.VOID_TYPE,
                        new Type[]{
                                Type.INT_TYPE,
                                Type.INT_TYPE,
                                Type.getType(Object[].class),
                                Type.getType(Object.class)
                        }
                )
        );

        throwException();
    }

    void processObject(String name) {
        Class<?> process = smithProcesses.get(name);

        if (process == null)
            return;

        invokeStatic(
                Type.getType(process),
                new Method(
                        "transform",
                        Type.getType(Object.class),
                        new Type[]{
                                Type.getType(Object.class)
                        }
                )
        );
    }

    private final int classID;
    private final int methodID;
    private final String className;
    private final boolean canBlock;
    private final boolean isStatic;
    private final boolean isConstructor;

    private final int returnVariable;
    private final int argumentsVariable;
    private final Label start;
    private final Label end;
    private final Label handler;
}
