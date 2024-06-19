package com.security.smith.processor;

import com.security.smith.log.SmithLogger;
import org.apache.commons.lang3.reflect.FieldUtils;

public class FileDescriptorProcessor {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        try {
            return FieldUtils.readField(object, "fd", true);
        } catch (Exception e) {
            SmithLogger.exception(e);
        }

        return "";
    }
}
