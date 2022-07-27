package com.security.patch;

import com.security.smith.log.SmithLogger;
import com.security.smith.module.Patch;
import javassist.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Optional;

public class CVE202144228 implements Patch, ClassFileTransformer {
    private static final String CLASS_NAME = "org.apache.logging.log4j.core.net.JndiManager";
    private static final String METHOD_NAME = "lookup";
    private final Instrumentation inst;

    public CVE202144228(Instrumentation inst) {
        this.inst = inst;
    }

    private void reload() {
        Class<?>[] cls = Arrays.stream(inst.getAllLoadedClasses())
                .filter(c -> c.getName().equals(CLASS_NAME))
                .toArray(Class<?>[]::new);

        SmithLogger.logger.info("reload: " + Arrays.toString(cls));

        try {
            inst.retransformClasses(cls);
        } catch (UnmodifiableClassException e) {
            SmithLogger.exception(e);
        }
    }

    @Override
    public void install() {
        inst.addTransformer(this, true);
        reload();
    }

    @Override
    public void uninstall() {
        inst.removeTransformer(this);
        reload();
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (!className.replace("/", ".").equals(CLASS_NAME))
            return null;

        SmithLogger.logger.info("transform: " + CLASS_NAME);

        CtClass cls = null;

        try {
            ClassPool pool = new ClassPool(true);

            if (loader != null)
                pool.appendClassPath(new LoaderClassPath(loader));

            cls = pool.makeClass(new ByteArrayInputStream(classfileBuffer));

            Optional<CtMethod> method = Arrays.stream(cls.getMethods())
                    .filter(m -> m.getName().equals(METHOD_NAME))
                    .findFirst();

            if (!method.isPresent()) {
                SmithLogger.logger.warning("no such method: " + METHOD_NAME);
                return null;
            }

            method.get().setBody("return null;");

            return cls.toBytecode();
        } catch (IOException | CannotCompileException e) {
            SmithLogger.exception(e);
        } finally {
            if (cls != null)
                cls.detach();
        }

        return null;
    }
}
