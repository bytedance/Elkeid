package com.security.smithloader.common;

import java.lang.management.ManagementFactory;

public class ProcessHelper {
    public static int getCurrentPID() {
        String name = ManagementFactory.getRuntimeMXBean().getName();
        return Integer.parseInt(name.split("@")[0]);
    }
}
