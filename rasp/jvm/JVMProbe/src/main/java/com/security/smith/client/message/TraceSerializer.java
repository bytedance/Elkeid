package com.security.smith.client.message;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import java.lang.reflect.Type;
import java.util.Arrays;

public class TraceSerializer implements JsonSerializer<Trace> {
    @Override
    public JsonElement serialize(Trace src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("classID", src.getClassID());
        jsonObject.addProperty("methodID", src.getMethodID());
        jsonObject.addProperty("blocked", src.isBlocked());
        jsonObject.addProperty("policyID", src.getPolicyID());
        jsonObject.add("ret", context.serialize(src.getRet(),RetConverter.class));
        jsonObject.add("args", context.serialize(src.getArgs(),ArgsConverter.class));
        jsonObject.add("stackTrace", context.serialize(convertStackTrace(src.getStackTrace())));
        return jsonObject;
    }

    private String[] convertStackTrace(StackTraceElement[] stackTrace) {
        if (stackTrace.length <= 2)
            return null;

        StackTraceElement[] elements = Arrays.copyOfRange(stackTrace, 2, stackTrace.length);
        String[] result = new String[elements.length];

        for (int i = 0; i < elements.length; i++) {
            result[i] = elements[i].toString();
        }

        return result;
    }
}