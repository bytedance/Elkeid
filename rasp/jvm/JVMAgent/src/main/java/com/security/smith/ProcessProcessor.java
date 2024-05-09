package com.security.smith.processor;

import com.security.smithloader.log.SmithAgentLogger;
import org.apache.commons.lang3.reflect.FieldUtils;

public class ProcessProcessor {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        try {
            return FieldUtils.readField(object, "pid", true);
        } catch (IllegalAccessException e) {
            SmithAgentLogger.exception(e);
        }

        return "";
    }
}
