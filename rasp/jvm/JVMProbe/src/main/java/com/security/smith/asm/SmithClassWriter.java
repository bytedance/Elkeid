package com.security.smith.asm;

import org.objectweb.asm.ClassWriter;

public class SmithClassWriter extends ClassWriter {
    public SmithClassWriter(int flags) {
        super(flags);
    }

    @Override
    protected ClassLoader getClassLoader() {
        return ClassLoader.getSystemClassLoader();
    }
}
