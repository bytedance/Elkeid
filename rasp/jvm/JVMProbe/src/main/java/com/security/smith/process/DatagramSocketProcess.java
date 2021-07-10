package com.security.smith.process;

import java.net.DatagramSocket;

public class DatagramSocketProcess {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return ((DatagramSocket)object).getLocalAddress();
    }
}
