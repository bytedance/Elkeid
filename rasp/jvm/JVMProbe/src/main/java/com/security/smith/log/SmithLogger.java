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
    private static FileHandler fileHandler = null;


    public static void loggerProberInit() {
        logger.setUseParentHandlers(false);

        try {
            String filename = String.format("/tmp/JVMProbe.%d.log", ProcessHelper.getCurrentPID());

            fileHandler = new FileHandler(filename, 5 * 1024 * 1024, 5, true);
            logger.addHandler(fileHandler);

            SimpleFormatter formatter = new SimpleFormatter();
            fileHandler.setFormatter(formatter);

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

    public static void loggerProberUnInit() {
        try {
            if (null != fileHandler) {
                Logger logger = Logger.getLogger("RASP");

                if (logger != null) {
                    logger.removeHandler(fileHandler);
                }
                fileHandler.close();
                fileHandler = null;
            }
        } catch (Throwable t) {

        }
    }
}
