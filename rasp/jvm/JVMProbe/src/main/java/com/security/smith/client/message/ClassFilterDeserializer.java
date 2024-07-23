package com.security.smith.client.message;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.security.smith.client.message.ClassFilter;
import com.security.smith.client.message.ClassFilter;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import java.lang.reflect.Type;

public class ClassFilterDeserializer implements com.google.gson.JsonDeserializer<ClassFilter> {
    @Override
    public ClassFilter deserialize(JsonElement json, Type typeOfT, com.google.gson.JsonDeserializationContext context) {
        JsonObject jsonObject = json.getAsJsonObject();
        ClassFilter filter = new ClassFilter();
        filter.setTransId();
        filter.setClassName(jsonObject.getAsJsonPrimitive("class_name").getAsString());
        filter.setClassPath(jsonObject.getAsJsonPrimitive("class_path").getAsString());
        filter.setInterfacesName(jsonObject.getAsJsonPrimitive("interfaces_name").getAsString());
        filter.setClassLoaderName(jsonObject.getAsJsonPrimitive("class_Loader_name").getAsString());
        filter.setParentClassName(jsonObject.getAsJsonPrimitive("parent_Class_name").getAsString());
        filter.setParentClassLoaderName(jsonObject.getAsJsonPrimitive("parent_class_Loader_name").getAsString());
        filter.setRuleId(jsonObject.getAsJsonPrimitive("rule_id").getAsInt());
        filter.setStackTrace(convertStackTrace(context.deserialize(jsonObject.get("stackTrace"), String[].class)));
        return filter;
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