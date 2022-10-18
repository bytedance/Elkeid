package com.security.smith.log;

import com.security.smith.common.ProcessHelper;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class SmithLogger {
    public static Logger logger = Logger.getLogger("RASP");

    static {
        logger.setUseParentHandlers(false);

        try {
            String filename = String.format("/tmp/JVMProbe.%d.%d.log", ProcessHelper.getCurrentPID(), Instant.now().getEpochSecond());

            FileHandler handler = new FileHandler(filename, true);
            logger.addHandler(handler);

            SimpleFormatter formatter = new SimpleFormatter();
            handler.setFormatter(formatter);

        } catch (IOException | NumberFormatException e) {
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
