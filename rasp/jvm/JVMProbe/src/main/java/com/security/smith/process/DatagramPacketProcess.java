package com.security.smith.process;

import java.net.DatagramPacket;

public class DatagramPacketProcess {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return ((DatagramPacket)object).getAddress();
    }
}
