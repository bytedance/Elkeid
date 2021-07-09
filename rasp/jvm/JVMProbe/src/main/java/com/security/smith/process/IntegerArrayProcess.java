package com.security.smith.process;

import java.util.Arrays;

public class IntegerArrayProcess {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return Arrays.toString((int[]) object);
    }
}
