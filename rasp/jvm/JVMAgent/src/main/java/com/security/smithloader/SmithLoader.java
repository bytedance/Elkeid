package com.security.smithloader;

import java.io.File;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;

public class SmithLoader extends ClassLoader {
      private File file;
      private JarFile jarFile;
    public SmithLoader(String jarFilePath, ClassLoader parent) throws IOException {
        file = new File(jarFilePath);
        this.jarFile = new JarFile(file);
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
            //throw e;
        }

        return null;
    }

    private byte[] readAllBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        return outputStream.toByteArray();
    }

    private byte[] loadClassData(String className) throws IOException {
        byte[] data = null;

        try {
            ZipEntry zEntry = jarFile.getEntry(className);
            if(zEntry == null) {
                throw new IOException("class not found");
            }

            try (InputStream inputStream = jarFile.getInputStream(zEntry)) {
                data = readAllBytes(inputStream);
                inputStream.close();
            }
        }
        catch(Exception e) {
            throw e;
        }

        return data;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            jarFile.close();
            jarFile = null;
        } finally {
            super.finalize();
        }
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        InputStream inputStream = findResourceAsStream(name);
        if (inputStream == null) {
            inputStream = super.getResourceAsStream(name);
        }
        return inputStream;
    }

    private InputStream findResourceAsStream(String name) {
        InputStream inputStream = null;

        if(name.length() <= 0) {
            throw new NullPointerException();
        }

        String resourcePath = name;

        try {
            ZipEntry zEntry = jarFile.getEntry(resourcePath);
            if(zEntry == null) {
                throw new IOException("resource not found");
            }

            inputStream = jarFile.getInputStream(zEntry);
        }
        catch(Exception e) {
            
        }

        return inputStream;
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

