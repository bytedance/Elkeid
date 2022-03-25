package com.security.smith.processor;

import java.util.Arrays;

public class ObjectArrayProcessor {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        if (!object.getClass().isArray()) {
            return null;
        }

        return Arrays.toString((Object[]) object);
    }
}
