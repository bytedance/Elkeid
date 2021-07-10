package com.security.smith.asm;

import org.objectweb.asm.Opcodes;

class SmithProbeNode extends SmithMethodNode {
    public SmithProbeNode(int api, int access, String name, String descriptor, String signature, String[] exceptions) {
        super(api, access, name, descriptor, signature, exceptions);
    }

    @Override
    public void visitCode() {
        super.visitCode();

        // push null
        visitInsn(Opcodes.ACONST_NULL);

        visitMethodInsn(
                Opcodes.INVOKEVIRTUAL,
                probeName,
                "trace",
                "(II[Ljava/lang/Object;Ljava/lang/Object;)V",
                false
        );
    }
}
