package com.security.smith.asm;

import com.security.smith.SmithProbe;
import com.security.smith.client.message.Trace;
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
    private final int classID;
    private final int methodID;
    private final Type classType;
    private final boolean canBlock;
    private final boolean isStatic;
    private final boolean isConstructor;
    private final int traceVariable;
    private final int returnVariable;
    private final Label start;
    private final Label end;
    private final Label handler;

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

        traceVariable = newLocal(Type.getType(Trace.class));
        returnVariable = newLocal(Type.getType(Object.class));

        isConstructor = name.equals("<init>");
        isStatic = (access & Opcodes.ACC_STATIC) != 0;
    }

    private void surplus() {
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

        invokeVirtual(
                Type.getType(SmithProbe.class),
                new Method(
                        "surplus",
                        Type.BOOLEAN_TYPE,
                        new Type[]{
                                Type.INT_TYPE,
                                Type.INT_TYPE
                        }
                )
        );
    }

    private void post() {
        invokeStatic(
                Type.getType(SmithProbe.class),
                new Method(
                        "getInstance",
                        Type.getType(SmithProbe.class),
                        new Type[]{}
                )
        );

        loadLocal(traceVariable);

        invokeVirtual(
                Type.getType(SmithProbe.class),
                new Method(
                        "post",
                        Type.VOID_TYPE,
                        new Type[]{
                                Type.getType(Trace.class)
                        }
                )
        );
    }

    private void newTrace() {
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
        loadArgArray();

        invokeVirtual(
                Type.getType(SmithProbe.class),
                new Method(
                        "newTrace",
                        Type.getType(Trace.class),
                        new Type[]{
                                Type.INT_TYPE,
                                Type.INT_TYPE,
                                Type.getType(Object[].class)
                        }
                )
        );
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

        visitInsn(ACONST_NULL);
        storeLocal(traceVariable);

        mark(start);

        if (!canBlock) {
            Label label = new Label();

            surplus();
            ifZCmp(EQ, label);

            newTrace();
            storeLocal(traceVariable);

            mark(label);
            return;
        }

        newTrace();
        storeLocal(traceVariable);

        invokeStatic(
                Type.getType(SmithProbe.class),
                new Method(
                        "getInstance",
                        Type.getType(SmithProbe.class),
                        new Type[]{}
                )
        );

        loadLocal(traceVariable);

        invokeVirtual(
                Type.getType(SmithProbe.class),
                new Method(
                        "detect",
                        Type.VOID_TYPE,
                        new Type[]{
                                Type.getType(Trace.class)
                        }
                )
        );

        Label label = new Label();

        surplus();
        ifZCmp(NE, label);

        visitInsn(ACONST_NULL);
        storeLocal(traceVariable);

        mark(label);
    }

    @Override
    protected void onMethodExit(int opcode) {
        super.onMethodExit(opcode);

        if (opcode == ATHROW)
            return;

        Label label = new Label();

        loadLocal(traceVariable);
        ifNull(label);

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

        loadLocal(traceVariable);
        loadLocal(returnVariable);

        invokeVirtual(
                Type.getType(Trace.class),
                new Method(
                        "setRet",
                        Type.VOID_TYPE,
                        new Type[]{
                                Type.getType(Object.class)
                        }
                )
        );

        post();
        mark(label);
    }

    @Override
    public void visitMaxs(final int maxStack, final int maxLocals) {
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

        storeLocal(traceVariable + 1, Type.getType(Exception.class));

        Label label = new Label();

        loadLocal(traceVariable);
        ifNull(label);
        post();
        mark(label);

        loadLocal(traceVariable + 1);
        throwException();

        super.visitMaxs(maxStack, maxLocals);
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
}
