package com.security.smith.client.message;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import java.lang.reflect.Type;

public class TraceDeserializer implements com.google.gson.JsonDeserializer<Trace> {
    @Override
    public Trace deserialize(JsonElement json, Type typeOfT, com.google.gson.JsonDeserializationContext context) {
        JsonObject jsonObject = json.getAsJsonObject();
        Trace trace = new Trace();
        trace.setClassID(jsonObject.getAsJsonPrimitive("class_id").getAsInt());
        trace.setMethodID(jsonObject.getAsJsonPrimitive("method_id").getAsInt());
        trace.setBlocked(jsonObject.getAsJsonPrimitive("blocked").getAsBoolean());
        trace.setPolicyID(jsonObject.getAsJsonPrimitive("policyID").getAsString());
        trace.setRet(context.deserialize(jsonObject.get("ret"), Object.class));
        trace.setArgs(context.deserialize(jsonObject.get("args"), Object[].class));
        trace.setStackTrace(convertStackTrace(context.deserialize(jsonObject.get("stackTrace"), String[].class)));
        return trace;
    }

    private StackTraceElement[] convertStackTrace(String[] stackTrace) {
        if (stackTrace == null)
            return new StackTraceElement[0];

        StackTraceElement[] result = new StackTraceElement[stackTrace.length];
        for (int i = 0; i < stackTrace.length; i++) {
            String[] parts = stackTrace[i].split(",");
            if (parts.length != 4) {
                continue;
            }
            String className = parts[0].trim();
            String methodName = parts[1].trim();
            String fileName = parts[2].trim();
            int lineNumber = Integer.parseInt(parts[3].trim());
            result[i] = new StackTraceElement(className, methodName, fileName, lineNumber);
        }
        return result;
    }
}