package com.security.smith.client;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;

public class MessageDeserializer extends StdDeserializer<Message> {
    protected MessageDeserializer() {
        super(Message.class);
    }

    protected MessageDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public Message deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode node = p.getCodec().readTree(p);

        Message message = new Message();

        message.setOperate(node.get("message_type").asInt());
        message.setData(node.get("data"));

        return message;
    }
}