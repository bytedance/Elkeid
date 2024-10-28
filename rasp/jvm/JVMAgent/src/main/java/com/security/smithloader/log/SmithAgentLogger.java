package com.security.smithloader.log;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import com.security.smithloader.common.ProcessHelper;

public class SmithAgentLogger {
    public static Logger logger = Logger.getLogger("RASPAgent");

    static {
        try {
            logger.setUseParentHandlers(false);
            String filename = String.format("/tmp/JVMAgent.%d.log", ProcessHelper.getCurrentPID());

            FileHandler handler = new FileHandler(filename, 5 * 1024 * 1024, 5, true);
            logger.addHandler(handler);

            SimpleFormatter formatter = new SimpleFormatter();
            handler.setFormatter(formatter);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void exception(Throwable tr) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);

        tr.printStackTrace(pw);

        logger.severe(sw.toString());
    }
}
