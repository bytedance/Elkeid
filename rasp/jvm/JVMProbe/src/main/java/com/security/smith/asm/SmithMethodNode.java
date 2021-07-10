package com.security.smith.asm;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

abstract class SmithMethodNode extends MethodNode {
    protected static final Map<String, String> smithProcesses;

    static {
        Yaml yaml = new Yaml();
        InputStream inputStream = SmithMethodNode.class.getResourceAsStream("/process.yaml");

        smithProcesses = yaml.load(inputStream);
    }

    public SmithMethodNode(int api, int access, String name, String descriptor, String signature, String[] exceptions) {
        super(api, access, name, descriptor, signature, exceptions);
    }

    @Override
    public void visitCode() {
        super.visitCode();

        int index = 0;
        int offset = 0;

        List<String> args = Arrays.stream(Type.getArgumentTypes(desc))
                .map(Type::getClassName)
                .collect(Collectors.toList());

        if (name.equals("<init>")) {
            offset = 1;
        } else if ((access & Opcodes.ACC_STATIC) == 0) {
            args.add(0, className.replace("/", "."));
        }

        visitMethodInsn(
                Opcodes.INVOKESTATIC,
                probeName,
                "getInstance",
                "()L" + probeName + ";",
                false
        );

        // warning: args length limit 127 cause by "BIPUSH"
        visitIntInsn(Opcodes.SIPUSH, classID);
        visitIntInsn(Opcodes.SIPUSH, methodID);
        visitIntInsn(Opcodes.BIPUSH, args.size());
        visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");

        for (String arg : args) {
            visitInsn(Opcodes.DUP);
            visitIntInsn(Opcodes.BIPUSH, index);

            switch (arg) {
                case "int":
                    visitVarInsn(Opcodes.ILOAD, index + offset);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            "java/lang/Integer",
                            "valueOf",
                            "(I)Ljava/lang/Integer;",
                            false
                    );
                    break;

                case "boolean":
                    visitVarInsn(Opcodes.ILOAD, index + offset);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            "java/lang/Boolean",
                            "valueOf",
                            "(Z)Ljava/lang/Boolean;",
                            false
                    );
                    break;

                case "long":
                    visitVarInsn(Opcodes.LLOAD, index + offset);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            "java/lang/Long",
                            "valueOf",
                            "(J)Ljava/lang/Long;",
                            false
                    );
                    break;

                case "float":
                    visitVarInsn(Opcodes.FLOAD, index + offset);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            "java/lang/Float",
                            "valueOf",
                            "(F)Ljava/lang/Float;",
                            false
                    );
                    break;

                case "double":
                    visitVarInsn(Opcodes.DLOAD, index + offset);
                    visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            "java/lang/Double",
                            "valueOf",
                            "(D)Ljava/lang/Double;",
                            false
                    );
                    break;

                default:
                    visitVarInsn(Opcodes.ALOAD, index + offset);
                    break;
            }

            // process argument
            String process = smithProcesses.get(arg);

            if (process != null) {
                visitMethodInsn(
                        Opcodes.INVOKESTATIC,
                        process,
                        "transform",
                        "(Ljava/lang/Object;)Ljava/lang/Object;",
                        false
                );
            }

            visitInsn(Opcodes.AASTORE);

            index ++;
        }
    }

    public void setClassID(int classID) {
        this.classID = classID;
    }

    public void setMethodID(int methodID) {
        this.methodID = methodID;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public void setProbeName(String probeName) {
        this.probeName = probeName;
    }

    protected int classID;
    protected int methodID;
    protected String className;
    protected String probeName;
}
