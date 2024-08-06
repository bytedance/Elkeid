package com.security.smith.client.message;

import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.security.smith.client.message.Trace;

import java.lang.reflect.Type;
import java.util.Arrays;

public class TraceSerializer implements JsonSerializer<Trace> {
    @Override
    public JsonElement serialize(Trace src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("class_id", src.getClassID());
        jsonObject.addProperty("method_id", src.getMethodID());
        jsonObject.addProperty("blocked", src.isBlocked());
        jsonObject.addProperty("policy_id",src.getPolicyID());
        jsonObject.add("ret",context.serialize(convertRet(src.getRet())));
        jsonObject.add("args",context.serialize(convertArgs(src.getArgs())));
        jsonObject.add("stack_trace", context.serialize(convertStackTrace(src.getStackTrace())));
        jsonObject.addProperty("types", src.getTypes());
        return jsonObject;
    }

    private String convertRet(Object value) {
        return String.valueOf(value);
    }

    private String[] convertArgs(Object[] value) {
        String[] result = new String[value.length];
        for (int i = 0; i < value.length; i++) {
            result[i] = String.valueOf(value[i]);
        }
        return result;
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