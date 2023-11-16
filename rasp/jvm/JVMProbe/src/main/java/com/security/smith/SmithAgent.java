package com.security.smith;

import com.security.smith.log.SmithLogger;

import java.lang.instrument.Instrumentation;

public class SmithAgent {
    public static void premain(String agentArgs, Instrumentation inst) {
        agentmain(agentArgs, inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        String probe = System.getProperty("rasp.probe");

        if (probe != null) {
            SmithLogger.logger.info("probe running");
            return;
        }

        System.setProperty("rasp.probe", "smith");

        SmithProbe.getInstance().setInst(inst);
        SmithProbe.getInstance().init();
        SmithProbe.getInstance().start();
    }
}
