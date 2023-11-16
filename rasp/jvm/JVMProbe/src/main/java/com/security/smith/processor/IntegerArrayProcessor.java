package com.security.smith.processor;

import java.util.Arrays;

public class IntegerArrayProcessor {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return Arrays.toString((int[]) object);
    }
}
