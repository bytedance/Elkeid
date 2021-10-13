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
                visitInsn(Opcodes.DUP);

            String name = returnType.getClassName();

            switch (name) {
                case "int":
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Integer.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Integer.class), Type.INT_TYPE),
                            false
                    );

                    break;

                case "boolean":
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Boolean.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Boolean.class), Type.BOOLEAN_TYPE),
                            false
                    );

                    break;

                case "long":
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Long.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Long.class), Type.LONG_TYPE),
                            false
                    );

                    break;

                case "float":
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Float.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Float.class), Type.FLOAT_TYPE),
                            false
                    );

                    break;

                case "double":
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Double.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Double.class), Type.DOUBLE_TYPE),
                            false
                    );

                    break;

                case "void":
                    visitInsn(Opcodes.ACONST_NULL);
                    break;

                default:
                    String process = smithProcesses.get(name);

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
            visitInsn(canBlock ? Opcodes.ICONST_1 : Opcodes.ICONST_0);

            visitMethodInsn(
                    Opcodes.INVOKEVIRTUAL,
                    Type.getInternalName(SmithProbe.class),
                    "trace",
                    Type.getMethodDescriptor(Type.VOID_TYPE, Type.INT_TYPE, Type.INT_TYPE, Type.getType(Object[].class), Type.getType(Object.class), Type.BOOLEAN_TYPE),
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
            String name = argumentType.getClassName();
            int size = argumentType.getSize();

            visitInsn(Opcodes.DUP);
            visitIntInsn(Opcodes.BIPUSH, index++);

            switch (name) {
                case "int":
                    visitVarInsn(Opcodes.ILOAD, variable);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Integer.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Integer.class), Type.INT_TYPE),
                            false
                    );

                    break;

                case "boolean":
                    visitVarInsn(Opcodes.ILOAD, variable);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Boolean.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Boolean.class), Type.BOOLEAN_TYPE),
                            false
                    );

                    break;

                case "long":
                    visitVarInsn(Opcodes.LLOAD, variable);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Long.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Long.class), Type.LONG_TYPE),
                            false
                    );

                    break;

                case "float":
                    visitVarInsn(Opcodes.FLOAD, variable);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Float.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Float.class), Type.FLOAT_TYPE),
                            false
                    );

                    break;

                case "double":
                    visitVarInsn(Opcodes.DLOAD, variable);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            Type.getInternalName(Double.class),
                            "valueOf",
                            Type.getMethodDescriptor(Type.getType(Double.class), Type.DOUBLE_TYPE),
                            false
                    );

                    break;

                default:
                    visitVarInsn(Opcodes.ALOAD, variable);

                    String process = smithProcesses.get(name);

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
            }

            visitInsn(Opcodes.AASTORE);
            variable += size;
        }

        mv.visitVarInsn(Opcodes.ASTORE, argumentsVariable);
        visitLabel(start);
    }

    @Override
    public void visitEnd() {
        super.visitEnd();

        visitLabel(end);
        visitInsn(Opcodes.NOP);
        visitLabel(handler);

        visitFrame(
                Opcodes.F_NEW,
                argumentTypes.size(),
                argumentTypes.stream().map(Type::getInternalName).toArray(String[]::new),
                1,
                new Object[]{Type.getInternalName(Exception.class)}
        );

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
        visitInsn(canBlock ? Opcodes.ICONST_1 : Opcodes.ICONST_0);

        visitMethodInsn(
                Opcodes.INVOKEVIRTUAL,
                Type.getInternalName(SmithProbe.class),
                "trace",
                Type.getMethodDescriptor(Type.VOID_TYPE, Type.INT_TYPE, Type.INT_TYPE, Type.getType(Object[].class), Type.getType(Object.class), Type.BOOLEAN_TYPE),
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
