package com.security.smith.client.message;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.JsonPrimitive;
import java.lang.reflect.Type;

public class RetConverter implements JsonSerializer<Object> {
    @Override
    public JsonElement serialize(Object src, Type typeOfSrc, JsonSerializationContext context) {
        if (src instanceof String) {
            return new JsonPrimitive((String) src);
        } else if (src instanceof Integer) {
            return new JsonPrimitive((Integer) src);
        } else {
            return context.serialize(src);
        }
    }
}