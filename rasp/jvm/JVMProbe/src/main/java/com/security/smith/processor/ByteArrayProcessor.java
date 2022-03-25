package com.security.smith.processor;

public class ByteArrayProcessor {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return new String((byte[])object).trim();
    }
}
