package com.security.smith.processor;

import java.net.ProtocolFamily;

public class ProtocolFamilyProcessor {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return ((ProtocolFamily)object).name();
    }
}
