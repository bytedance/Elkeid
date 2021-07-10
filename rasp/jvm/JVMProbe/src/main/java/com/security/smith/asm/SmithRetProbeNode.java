package com.security.smith.asm;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.List;

class SmithRetProbeNode extends SmithMethodNode {
    private final List<AbstractInsnNode> retInstructions = new ArrayList<>();

    public SmithRetProbeNode(int api, int access, String name, String descriptor, String signature, String[] exceptions) {
        super(api, access, name, descriptor, signature, exceptions);
    }

    @Override
    public void visitInsn(int opcode) {
        super.visitInsn(opcode);

        if (opcode == Opcodes.IRETURN || opcode == Opcodes.FRETURN || opcode == Opcodes.ARETURN
                || opcode == Opcodes.LRETURN || opcode == Opcodes.DRETURN) {
            retInstructions.add(instructions.getLast());
        }
    }

    @Override
    public void visitEnd() {
        super.visitEnd();

        for (AbstractInsnNode retNode: retInstructions) {
            InsnList probeInstructions = new InsnList();

            probeInstructions.add(new InsnNode(Opcodes.DUP));

            int loadOp;
            int retVar = maxLocals;

            String returnType = Type.getReturnType(desc).getClassName();

            switch (returnType) {
                case "int":
                    loadOp = Opcodes.ILOAD;

                    probeInstructions.add(new VarInsnNode(Opcodes.ISTORE, retVar));
                    probeInstructions.add(
                            new MethodInsnNode(
                                    Opcodes.INVOKESTATIC,
                                    "java/lang/Integer",
                                    "valueOf",
                                    "(I)Ljava/lang/Integer;",
                                    false
                            )
                    );
                    break;

                case "boolean":
                    loadOp = Opcodes.ILOAD;

                    probeInstructions.add(new VarInsnNode(Opcodes.ISTORE, retVar));
                    probeInstructions.add(
                            new MethodInsnNode(
                                    Opcodes.INVOKESTATIC,
                                    "java/lang/Boolean",
                                    "valueOf",
                                    "(Z)Ljava/lang/Boolean;",
                                    false
                            )
                    );
                    break;

                case "long":
                    loadOp = Opcodes.LLOAD;

                    probeInstructions.add(new VarInsnNode(Opcodes.LSTORE, retVar));
                    probeInstructions.add(
                            new MethodInsnNode(
                                    Opcodes.INVOKESTATIC,
                                    "java/lang/Long",
                                    "valueOf",
                                    "(J)Ljava/lang/Long;",
                                    false
                            )
                    );
                    break;

                case "float":
                    loadOp = Opcodes.FLOAD;

                    probeInstructions.add(new VarInsnNode(Opcodes.FSTORE, retVar));
                    probeInstructions.add(
                            new MethodInsnNode(
                                    Opcodes.INVOKESTATIC,
                                    "java/lang/Float",
                                    "valueOf",
                                    "(F)Ljava/lang/Float;",
                                    false
                            )
                    );
                    break;

                case "double":
                    loadOp = Opcodes.DLOAD;

                    probeInstructions.add(new VarInsnNode(Opcodes.DSTORE, retVar));
                    probeInstructions.add(
                            new MethodInsnNode(
                                    Opcodes.INVOKESTATIC,
                                    "java/lang/Double",
                                    "valueOf",
                                    "(D)Ljava/lang/Double;",
                                    false
                            )
                    );
                    break;

                default:
                    loadOp = Opcodes.ALOAD;
                    probeInstructions.add(new VarInsnNode(Opcodes.ASTORE, retVar));
                    break;
            }

            // process argument
            String process = smithProcesses.get(returnType);

            if (process != null) {
                probeInstructions.add(
                        new MethodInsnNode(
                                Opcodes.INVOKESTATIC,
                                process,
                                "transform",
                                "(Ljava/lang/Object;)Ljava/lang/Object;",
                                false
                        )
                );
            }

            probeInstructions.add(
                    new MethodInsnNode(
                            Opcodes.INVOKEVIRTUAL,
                            probeName,
                            "trace",
                            "(II[Ljava/lang/Object;Ljava/lang/Object;)V",
                            false
                    )
            );

            // recover ret
            probeInstructions.add(new VarInsnNode(loadOp, retVar));

            instructions.insertBefore(retNode, probeInstructions);
        }
    }
}
