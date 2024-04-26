package com.security.smithloader;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;

public class SmithLoader extends ClassLoader {
      private JarFile jarFile;
    public SmithLoader(String jarFilePath, ClassLoader parent) throws IOException {
        this.jarFile = new JarFile(new File(jarFilePath));
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        try {
            String className = name.replace('.', '/') + ".class";
            try {
                byte[] classData = loadClassData(className);
                if (classData != null) {
                    return defineClass(name, classData, 0, classData.length);
                }
            } catch (IOException ex) {
                throw new ClassNotFoundException("Failed to load class: " + name, ex);
            }
        } catch (ClassNotFoundException e) {
            // If the class is not found in JAR file,try to load from parent class loader
            return super.findClass(name);
        }

        return null;
    }

    private byte[] loadClassData(String className) throws IOException {
        byte[] bytes = null;

        try {
            ZipEntry zEntry = jarFile.getEntry(className);
            if(zEntry == null) {
                throw new IOException("class not found");
            }

            InputStream inputStream = jarFile.getInputStream(zEntry);
            if(inputStream == null) {
                throw new IOException("class not found");
            }

            bytes = new byte[inputStream.available()];

            int bytesRead = inputStream.read(bytes);
            if (bytesRead != bytes.length) {
                throw new IOException("get byte array fail");
            }
        }
        catch(Exception e) {
            throw e;
        }

        return bytes;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            jarFile = null;
        } finally {
            super.finalize();
        }
    }

    public String getJarMainClass() {
        try {
            Manifest manifest = jarFile.getManifest();
            if (manifest != null) {
                Attributes attributes = manifest.getMainAttributes();
                return attributes.getValue(Attributes.Name.MAIN_CLASS);
            }
        }
        catch(IOException e) {

        }

        return null;
    }
}

