package com.security.smith.process;

import java.util.Arrays;

public class ObjectArrayProcess {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        if (!object.getClass().isArray()) {
            return null;
        }

        return Arrays.toString((Object[]) object);
    }
}
