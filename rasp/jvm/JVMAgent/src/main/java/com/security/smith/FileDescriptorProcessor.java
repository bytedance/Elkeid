package com.security.smith.processor;

import com.security.smithloader.log.SmithAgentLogger;
import org.apache.commons.lang3.reflect.FieldUtils;

public class FileDescriptorProcessor {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        try {
            return FieldUtils.readField(object, "fd", true);
        } catch (Throwable e) {
            SmithAgentLogger.exception(e);
        }

        return "";
    }
}
