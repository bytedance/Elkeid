package com.security.smith.asm;

//import com.security.smith.SmithProbeProxy;
import com.security.smith.processor.*;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;
import java.util.function.Function;

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
    private int stopWatchVariable;
    private int stopWatchTotalVariable;
    private final int argumentsVariable;
    private final int returnVariable;
    private final Label start;
    private final Label end;
    private final Label handler;
    private String preHook;
    private String postHook;
    private String exceptionHook;
    private String xHook;
    // just fo benchmark test
    private final boolean isBenchMark;

    private final Map<String, Class<?>> smithProcessors = new HashMap<String, Class<?>>() {{
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

    protected SmithMethodVisitor(int api, Type classType, int classID, int methodID, boolean canBlock, MethodVisitor methodVisitor, int access, String name, String descriptor, String pre_hook, String post_hook,String exception_hook) {
        super(api, methodVisitor, access, name, descriptor);

        this.classType = classType;
        this.classID = classID;
        this.methodID = methodID;
        this.canBlock = canBlock;
        this.preHook = pre_hook;
        this.postHook = post_hook;
        this.exceptionHook = exception_hook;
        this.isBenchMark = false;

        start = new Label();
        end = new Label();
        handler = new Label();

        argumentsVariable = newLocal(Type.getType(Object[].class));
        if (isBenchMark) {
            stopWatchTotalVariable = newLocal(Type.getType(StopWatch.class));
            stopWatchVariable = newLocal(Type.getType(StopWatch.class));
        }
        
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
        if (isBenchMark) {
                invokeStatic(
                        Type.getType(StopWatch.class),
                        new Method(
                                "createStarted",
                                Type.getType(StopWatch.class),
                                new Type[]{}
                        )
                );

                storeLocal(stopWatchTotalVariable);

                invokeStatic(
                        Type.getType(StopWatch.class),
                        new Method(
                                "createStarted",
                                Type.getType(StopWatch.class),
                                new Type[]{}
                        )
                );

                storeLocal(stopWatchVariable);
        }

        loadArgArray();
        storeLocal(argumentsVariable);

        visitInsn(ACONST_NULL);
        storeLocal(returnVariable);

        mark(start);

        if (preHook == null || preHook == "") {
            if (!canBlock) {
                if (isBenchMark) {
                        loadLocal(stopWatchVariable);

                        invokeVirtual(
                                Type.getType(StopWatch.class),
                                new Method(
                                        "suspend",
                                        Type.VOID_TYPE,
                                        new Type[]{}
                                )
                        );
                }
                
                return;
            } else {
                preHook = "detect";
            }
        }

        push(preHook);
        push(classID);
        push(methodID);
        loadLocal(argumentsVariable);

        invokeStatic(
                Type.getType("Lcom/security/smithloader/SmithAgent;"),
                new Method(
                        "PreProxy",
                        Type.VOID_TYPE,
                        new Type[]{
                            Type.getType(Object.class),
                                Type.INT_TYPE,
                                Type.INT_TYPE,
                                Type.getType(Object[].class)
                        }
                )
        );
        if (isBenchMark) {
                loadLocal(stopWatchVariable);

                invokeVirtual(
                        Type.getType(StopWatch.class),
                        new Method(
                                "suspend",
                                Type.VOID_TYPE,
                                new Type[]{}
                        )
                );
        }
    }

    @Override
    protected void onMethodExit(int opcode) {
        super.onMethodExit(opcode);

        if (opcode == ATHROW) {
            return;
        }
        if (isBenchMark) {
                loadLocal(stopWatchVariable);

                invokeVirtual(
                        Type.getType(StopWatch.class),
                        new Method(
                                "resume",
                                Type.VOID_TYPE,
                                new Type[]{}
                        )
                );
        }

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

        if (postHook == null || postHook == "") {
            postHook = "trace";
        }

        push(postHook);
        push(classID);
        push(methodID);
        loadLocal(argumentsVariable);
        loadLocal(returnVariable);
        push(false);

        invokeStatic(
                Type.getType("Lcom/security/smithloader/SmithAgent;"),
                new Method(
                        "PostProxy",
                        Type.VOID_TYPE,
                        new Type[]{
                            Type.getType(Object.class),
                                Type.INT_TYPE,
                                Type.INT_TYPE,
                                Type.getType(Object[].class),
                                Type.getType(Object.class),
                                Type.BOOLEAN_TYPE
                        }
                )
        );

        if (isBenchMark) {
                loadLocal(stopWatchVariable);

                invokeVirtual(
                        Type.getType(StopWatch.class),
                        new Method(
                                "stop",
                                Type.VOID_TYPE,
                                new Type[]{}
                        )
                );

                loadLocal(stopWatchTotalVariable);

                invokeVirtual(
                        Type.getType(StopWatch.class),
                        new Method(
                                "stop",
                                Type.VOID_TYPE,
                                new Type[]{}
                        )
                );

                push(classID);
                push(methodID);
                loadLocal(stopWatchVariable);

                invokeVirtual(
                        Type.getType(StopWatch.class),
                        new Method(
                                "getNanoTime",
                                Type.LONG_TYPE,
                                new Type[]{}
                        )
                );

                loadLocal(stopWatchTotalVariable);

                invokeVirtual(
                        Type.getType(StopWatch.class),
                        new Method(
                                "getNanoTime",
                                Type.LONG_TYPE,
                                new Type[]{}
                        )
                );

                invokeStatic(
                        Type.getType("Lcom/security/smithloader/SmithAgent;"),
                        new Method(
                                "RecordProxy",
                                Type.VOID_TYPE,
                                new Type[]{
                                        Type.INT_TYPE,
                                        Type.INT_TYPE,
                                        Type.LONG_TYPE,
                                        Type.LONG_TYPE
                                }
                        )
                );
        }
    }

    class TypeMapper implements Function<Type, Object> {
    @Override
    public Object apply(Type t) {
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
    }
}
    @Override
    public void visitMaxs(final int maxStack, final int maxLocals) {
        mark(end);
        mark(handler);

        if (exceptionHook == null || exceptionHook == "") {

            if (postHook == null || postHook == "") {
                xHook = "trace";
            } else {
                xHook = postHook;
            }

            Type[] types = Type.getArgumentTypes(methodDesc);

            if (!isStatic) {
                types = ArrayUtils.addFirst(types, classType);
            }

            Function<Type, Object> typeMapper = new TypeMapper();
            Object[] local = Arrays.stream(types).map(typeMapper).toArray();

            visitFrame(
                    Opcodes.F_NEW,
                    local.length,
                    local,
                    1,
                    new Object[]{Type.getInternalName(Exception.class)}
            );

            storeLocal(returnVariable + 1, Type.getType(Exception.class));

            push(xHook);
            push(classID);
            push(methodID);
            loadLocal(argumentsVariable);
            visitInsn(Opcodes.ACONST_NULL);

            if (!canBlock) {
                push(false);
            } else {
                loadLocal(returnVariable + 1);
                instanceOf(Type.getType(SecurityException.class));
            }

            invokeStatic(
                    Type.getType("Lcom/security/smithloader/SmithAgent;"),
                    new Method(
                            "PostProxy",
                            Type.VOID_TYPE,
                            new Type[]{
                                Type.getType(Object.class),
                                    Type.INT_TYPE,
                                    Type.INT_TYPE,
                                    Type.getType(Object[].class),
                                    Type.getType(Object.class),
                                    Type.BOOLEAN_TYPE
                            }
                    )
            );

            loadLocal(returnVariable + 1);
            throwException();

            super.visitMaxs(maxStack, maxLocals);
        }
        else {
            int newLocal = newLocal(Type.getType(Exception.class));
            int retId = newLocal(Type.getType(Object.class));

            storeLocal(newLocal,Type.getType(Exception.class));
            loadLocal(newLocal);

            push(exceptionHook);
            push(classID);
            push(methodID);
            loadLocal(argumentsVariable);
            loadLocal(newLocal);

            invokeStatic(
                    Type.getType("Lcom/security/smithloader/SmithAgent;"),
                    new Method(
                            "ExceptionProxy",
                            Type.getType(Object.class),
                            new Type[]{
                                Type.getType(Object.class),
                                    Type.INT_TYPE,
                                    Type.INT_TYPE,
                                    Type.getType(Object[].class),
                                    Type.getType(Object.class)
                            }
                    )
            );

            mv.visitVarInsn(ASTORE, retId);
            mv.visitVarInsn(ALOAD, retId);
            Label label_if = new Label();
            mv.visitJumpInsn(IFNULL, label_if);
            mv.visitVarInsn(ALOAD, retId);
            mv.visitTypeInsn(CHECKCAST, "java/lang/Class");
            mv.visitInsn(ARETURN);
            mv.visitLabel(label_if);
            loadLocal(newLocal);
            throwException();

            super.visitMaxs(maxStack, maxLocals);
        } 
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
