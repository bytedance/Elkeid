package com.security.smith.processor;

import java.net.DatagramSocket;

public class DatagramSocketProcessor {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return ((DatagramSocket)object).getLocalAddress();
    }
}
