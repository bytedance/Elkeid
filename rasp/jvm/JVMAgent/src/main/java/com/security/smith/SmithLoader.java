package com.security.smith;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

public class SmithLoader extends URLClassLoader {
      private JarFile jarFile;

    public SmithLoader(URL jarFileURL, ClassLoader parent) throws IOException {
        super(new URL[] { jarFileURL }, parent);
        this.jarFile = new JarFile(new File(jarFileURL.getFile()));
    }

    public SmithLoader(String jarFilePath, ClassLoader parent) throws IOException {
        URL jarFileURL = new URL(jarFilePath);
        
        super(new URL[] { jarFileURL }, parent);
        this.jarFile = new JarFile(new File(jarFileURL.getFile()));
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        try {
            return super.findClass(name);
        } catch (ClassNotFoundException e) {
            // If the class is not found by the parent class loader, try to load it from the JAR file
            String className = name.replace('.', '/') + ".class";
            try {
                byte[] classData = loadClassData(className);
                if (classData != null) {
                    return defineClass(name, classData, 0, classData.length);
                }
            } catch (IOException ex) {
                throw new ClassNotFoundException("Failed to load class: " + name, ex);
            }
            throw new ClassNotFoundException(name);
        }
    }

    private byte[] loadClassData(String className) throws IOException {
        return jarFile.getInputStream(jarFile.getEntry(className)).readAllBytes();
    }

    public String getJarMainClass() {
        Manifest manifest = jarFile.getManifest();
        if (manifest != null) {
            Attributes attributes = manifest.getMainAttributes();
            return attributes.getValue(Attributes.Name.MAIN_CLASS);
        }
        return null;
    }
}
