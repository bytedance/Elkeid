package com.security.smith.asm;

import com.security.smith.SmithProbe;
import com.security.smith.processor.*;
import org.apache.commons.lang3.ArrayUtils;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SmithMethodVisitor extends AdviceAdapter {
    private static final Map<String, Class<?>> smithProcessors = new HashMap<String, Class<?>>() {{
        put("byte[]", ByteArrayProcessor.class);
        put("int[]", IntegerArrayProcessor.class);
        put("java.net.ProtocolFamily", ProtocolFamilyProcessor.class);
        put("java.io.FileDescriptor", FileDescriptorProcessor.class);
        put("java.net.URL[]", ObjectArrayProcessor.class);
        put("java.net.DatagramPacket", DatagramPacketProcessor.class);
        put("java.net.DatagramSocket", DatagramSocketProcessor.class);
        put("java.lang.String[]", ObjectArrayProcessor.class);
        put("java.lang.Process", ProcessProcessor.class);
        put("java.lang.UNIXProcess", ProcessProcessor.class);
        put("java.lang.ProcessImpl", ProcessProcessor.class);
        put("java.net.InetAddress[]", ObjectArrayProcessor.class);
    }};

    protected SmithMethodVisitor(int api, Type classType, int classID, int methodID, boolean canBlock, MethodVisitor methodVisitor, int access, String name, String descriptor) {
        super(api, methodVisitor, access, name, descriptor);

        this.classType = classType;
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
            processObject(classType.getClassName());
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

        visitInsn(ACONST_NULL);
        storeLocal(returnVariable);

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
                processObject(classType.getClassName());
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

        Type[] types = Type.getArgumentTypes(methodDesc);

        if (!isStatic) {
            types = ArrayUtils.addFirst(types, classType);
        }

        Object[] local = Arrays.stream(types).map(t -> {
            switch (t.getSort()) {
                case Type.BOOLEAN:
                case Type.CHAR:
                case Type.BYTE:
                case Type.SHORT:
                case Type.INT:
                    return Opcodes.INTEGER;
                case Type.FLOAT:
                    return Opcodes.FLOAT;
                case Type.ARRAY:
                case Type.OBJECT:
                    return t.getInternalName();
                case Type.LONG:
                    return Opcodes.LONG;
                case Type.DOUBLE:
                    return Opcodes.DOUBLE;
                default:
                    throw new AssertionError();
            }
        }).toArray();

        visitFrame(
                Opcodes.F_NEW,
                local.length,
                local,
                1,
                new Object[]{Type.getInternalName(Exception.class)}
        );

        storeLocal(returnVariable + 1, Type.getType(Exception.class));

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

        loadLocal(returnVariable + 1);
        throwException();
    }

    void processObject(String name) {
        Class<?> processor = smithProcessors.get(name);

        if (processor == null)
            return;

        invokeStatic(
                Type.getType(processor),
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
    private final Type classType;
    private final boolean canBlock;
    private final boolean isStatic;
    private final boolean isConstructor;

    private final int returnVariable;
    private final int argumentsVariable;
    private final Label start;
    private final Label end;
    private final Label handler;
}
