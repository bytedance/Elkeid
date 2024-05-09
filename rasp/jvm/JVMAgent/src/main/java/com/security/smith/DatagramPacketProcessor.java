package com.security.smith.processor;

import java.net.DatagramPacket;

public class DatagramPacketProcessor {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        return ((DatagramPacket)object).getAddress();
    }
}
