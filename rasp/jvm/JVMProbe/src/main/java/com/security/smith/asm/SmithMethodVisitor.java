package com.security.smith.asm;

import com.security.smith.SmithProbe;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.LocalVariablesSorter;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class SmithMethodVisitor extends LocalVariablesSorter {
    protected static final Map<String, String> smithProcesses;

    static {
        Yaml yaml = new Yaml();
        InputStream inputStream = SmithMethodVisitor.class.getResourceAsStream("/process.yaml");

        smithProcesses = yaml.load(inputStream);
    }

    protected SmithMethodVisitor(int api, int access, Type classType, int classID, int methodID, boolean canBlock, String name, String descriptor, MethodVisitor methodVisitor) {
        super(api, access, descriptor, methodVisitor);

        this.classID = classID;
        this.methodID = methodID;
        this.canBlock = canBlock;

        start = new Label();
        end = new Label();
        handler = new Label();

        argumentsVariable = newLocal(Type.getType(Object[].class));
        returnVariable = newLocal(Type.getType(Object.class));

        returnType = Type.getReturnType(descriptor);
        argumentTypes = new ArrayList<>(Arrays.asList(Type.getArgumentTypes(descriptor)));

        if (name.equals("<init>")) {
            skip = 1;
        }

        if ((access & Opcodes.ACC_STATIC) == 0) {
            argumentTypes.add(0, classType);
        }
    }

    @Override
    public void visitInsn(int opcode) {
        if (opcode == Opcodes.RETURN || opcode == Opcodes.IRETURN || opcode == Opcodes.FRETURN || opcode == Opcodes.ARETURN || opcode == Opcodes.LRETURN || opcode == Opcodes.DRETURN) {
            if (opcode != Opcodes.RETURN)
                visitInsn(returnType.getSize() == 2 ? Opcodes.DUP2 : Opcodes.DUP);

            switch (returnType.getSort()) {
                case Type.VOID:
                    visitInsn(Opcodes.ACONST_NULL);
                    break;

                case Type.BOOLEAN:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Boolean.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Boolean.class), Type.BOOLEAN_TYPE),
                            false
                    );

                    break;

                case Type.CHAR:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Character.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Character.class), Type.CHAR_TYPE),
                            false
                    );

                    break;

                case Type.BYTE:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Byte.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Byte.class), Type.BYTE_TYPE),
                            false
                    );

                    break;

                case Type.SHORT:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Short.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Short.class), Type.SHORT_TYPE),
                            false
                    );

                    break;

                case Type.INT:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Integer.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Integer.class), Type.INT_TYPE),
                            false
                    );

                    break;

                case Type.FLOAT:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Float.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Float.class), Type.FLOAT_TYPE),
                            false
                    );

                    break;

                case Type.LONG:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Long.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Long.class), Type.LONG_TYPE),
                            false
                    );

                    break;

                case Type.DOUBLE:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Double.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Double.class), Type.DOUBLE_TYPE),
                            false
                    );

                    break;

                case Type.ARRAY:
                case Type.OBJECT:
                    String process = smithProcesses.get(returnType.getClassName());

                    if (process == null)
                        break;

                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            process,
                            "transform",
                            Type.getMethodDescriptor(Type.getType(Object.class), Type.getType(Object.class)),
                            false
                    );

                    break;

                default:
                    throw new AssertionError();
            }

            mv.visitVarInsn(Opcodes.ASTORE, returnVariable);

            visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    Type.getInternalName(SmithProbe.class),
                    "getInstance",
                    Type.getMethodDescriptor(Type.getType(SmithProbe.class)),
                    false
            );

            visitIntInsn(Opcodes.SIPUSH, classID);
            visitIntInsn(Opcodes.SIPUSH, methodID);
            mv.visitVarInsn(Opcodes.ALOAD, argumentsVariable);
            mv.visitVarInsn(Opcodes.ALOAD, returnVariable);

            visitMethodInsn(
                    Opcodes.INVOKEVIRTUAL,
                    Type.getInternalName(SmithProbe.class),
                    "trace",
                    Type.getMethodDescriptor(Type.VOID_TYPE, Type.INT_TYPE, Type.INT_TYPE, Type.getType(Object[].class), Type.getType(Object.class)),
                    false
            );
        }

        super.visitInsn(opcode);
    }

    @Override
    public void visitCode() {
        super.visitCode();

        int index = 0;
        int variable = skip;

        visitTryCatchBlock(start, end, handler, Type.getInternalName(Exception.class));

        visitIntInsn(Opcodes.BIPUSH, argumentTypes.size() - skip);
        visitTypeInsn(Opcodes.ANEWARRAY, Type.getInternalName(Object.class));

        for (Type argumentType : argumentTypes.subList(skip, argumentTypes.size())) {
            int size = argumentType.getSize();

            visitInsn(size == 2 ? Opcodes.DUP2 : Opcodes.DUP);
            visitIntInsn(Opcodes.BIPUSH, index++);
            visitVarInsn(argumentType.getOpcode(Opcodes.ILOAD), variable);

            switch (argumentType.getSort()) {
                case Type.BOOLEAN:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Boolean.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Boolean.class), Type.BOOLEAN_TYPE),
                            false
                    );

                    break;

                case Type.CHAR:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Character.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Character.class), Type.CHAR_TYPE),
                            false
                    );

                    break;

                case Type.BYTE:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Byte.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Byte.class), Type.BYTE_TYPE),
                            false
                    );

                    break;

                case Type.SHORT:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Short.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Short.class), Type.SHORT_TYPE),
                            false
                    );

                    break;

                case Type.INT:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Integer.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Integer.class), Type.INT_TYPE),
                            false
                    );

                    break;

                case Type.FLOAT:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Float.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Float.class), Type.FLOAT_TYPE),
                            false
                    );

                    break;

                case Type.LONG:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Long.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Long.class), Type.LONG_TYPE),
                            false
                    );

                    break;

                case Type.DOUBLE:
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Double.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Double.class), Type.DOUBLE_TYPE),
                            false
                    );

                    break;

                case Type.ARRAY:
                case Type.OBJECT:
                    String process = smithProcesses.get(argumentType.getClassName());

                    if (process == null)
                        break;

                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            process,
                            "transform",
                            Type.getMethodDescriptor(Type.getType(Object.class), Type.getType(Object.class)),
                            false
                    );

                    break;

                default:
                    throw new AssertionError();
            }

            visitInsn(Opcodes.AASTORE);
            variable += size;
        }

        mv.visitVarInsn(Opcodes.ASTORE, argumentsVariable);
        visitLabel(start);

        if (!canBlock)
            return;

        visitMethodInsn(
                Opcodes.INVOKESTATIC,
                Type.getInternalName(SmithProbe.class),
                "getInstance",
                Type.getMethodDescriptor(Type.getType(SmithProbe.class)),
                false
        );

        visitIntInsn(Opcodes.SIPUSH, classID);
        visitIntInsn(Opcodes.SIPUSH, methodID);
        mv.visitVarInsn(Opcodes.ALOAD, argumentsVariable);

        visitMethodInsn(
                Opcodes.INVOKEVIRTUAL,
                Type.getInternalName(SmithProbe.class),
                "detect",
                Type.getMethodDescriptor(Type.VOID_TYPE, Type.INT_TYPE, Type.INT_TYPE, Type.getType(Object[].class)),
                false
        );
    }

    @Override
    public void visitEnd() {
        super.visitEnd();

        visitLabel(end);
        visitLabel(handler);

        /*
        If you want to generate a class to be loaded from file, need to add stack map frame here cause by JVM verify class when loading.
        In addition, the try block in constructor should start after superclass constructor called, because the first local variable before that was uninitializedThis instead of this.
         */

        mv.visitVarInsn(Opcodes.ASTORE, returnVariable + 1);

        visitMethodInsn(
                Opcodes.INVOKESTATIC,
                Type.getInternalName(SmithProbe.class),
                "getInstance",
                Type.getMethodDescriptor(Type.getType(SmithProbe.class)),
                false
        );

        visitIntInsn(Opcodes.SIPUSH, classID);
        visitIntInsn(Opcodes.SIPUSH, methodID);
        mv.visitVarInsn(Opcodes.ALOAD, argumentsVariable);
        visitInsn(Opcodes.ACONST_NULL);

        visitMethodInsn(
                Opcodes.INVOKEVIRTUAL,
                Type.getInternalName(SmithProbe.class),
                "trace",
                Type.getMethodDescriptor(Type.VOID_TYPE, Type.INT_TYPE, Type.INT_TYPE, Type.getType(Object[].class), Type.getType(Object.class)),
                false
        );

        mv.visitVarInsn(Opcodes.ALOAD, returnVariable + 1);
        visitInsn(Opcodes.ATHROW);
    }

    private final int classID;
    private final int methodID;
    private final boolean canBlock;

    private int skip;
    private final int returnVariable;
    private final int argumentsVariable;
    private final Label start;
    private final Label end;
    private final Label handler;
    private final Type returnType;
    private final List<Type> argumentTypes;
}
