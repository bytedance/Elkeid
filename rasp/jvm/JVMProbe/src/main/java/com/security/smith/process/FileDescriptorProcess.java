package com.security.smith.process;

import com.security.smith.log.SmithLogger;
import org.apache.commons.lang3.reflect.FieldUtils;

public class FileDescriptorProcess {
    public static Object transform(Object object) {
        if (object == null)
            return null;

        try {
            return FieldUtils.readField(object, "fd", true);
        } catch (IllegalAccessException e) {
            SmithLogger.exception(e);
        }

        return "";
    }
}
