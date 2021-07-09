package com.security.smith.process;

public class ByteArrayProcess {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return new String((byte[])object).trim();
    }
}
