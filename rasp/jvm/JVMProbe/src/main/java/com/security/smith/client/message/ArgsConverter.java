package com.security.smith.client.message;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import java.lang.reflect.Type;

public class ArgsConverter implements JsonSerializer<Object[]> {
    @Override
    public JsonElement serialize(Object[] src, Type typeOfSrc, JsonSerializationContext context) {
        JsonArray jsonArray = new JsonArray();
        for (Object arg : src) {
            if (arg instanceof String) {
                jsonArray.add(new JsonPrimitive((String) arg));
            } else if (arg instanceof Integer) {
                jsonArray.add(new JsonPrimitive((Integer) arg));
            } else {
                jsonArray.add(context.serialize(arg));
            }
        }
        return jsonArray;
    }
}
