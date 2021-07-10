package com.security.smith.process;

import java.net.ProtocolFamily;

public class ProtocolFamilyProcess {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return ((ProtocolFamily)object).name();
    }
}
