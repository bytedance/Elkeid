package com.security.smith.client.message;

import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.security.smith.client.message.ClassFilter;
import com.security.smith.client.message.Trace;

import java.lang.reflect.Type;
import java.util.Arrays;

public class ClassFilterSerializer implements JsonSerializer<ClassFilter> {
    @Override
    public JsonElement serialize(ClassFilter src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("trans_id", src.getTransId());
        jsonObject.addProperty("class_name", src.getClassName());
        jsonObject.addProperty("class_path", src.getClassPath());
        jsonObject.addProperty("interfaces_name", src.getInterfacesName());
        jsonObject.addProperty("class_Loader_name", src.getClassLoaderName());
        jsonObject.addProperty("parent_Class_name", src.getParentClassName());
        jsonObject.addProperty("parent_class_Loader_name", src.getParentClassLoaderName());
        jsonObject.addProperty("rule_id", src.getRuleId());
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