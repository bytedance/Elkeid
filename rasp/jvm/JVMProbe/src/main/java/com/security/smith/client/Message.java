package com.security.smith.client;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import io.netty.handler.codec.ReplayingDecoder;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;

@JsonSerialize(using = MessageSerializer.class)
@JsonDeserialize(using = MessageDeserializer.class)
public class Message {
    static final int PROTOCOL_HEADER_SIZE = 4;
    static final int MAX_PAYLOAD_SIZE = 10240;

    private int operate;
    private JsonNode data;

    int getOperate() {
        return operate;
    }

    public void setOperate(int operate) {
        this.operate = operate;
    }

    public JsonNode getData() {
        return data;
    }

    public void setData(JsonNode data) {
        this.data = data;
    }
}


class MessageDeserializer extends StdDeserializer<Message> {
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

class MessageEncoder extends MessageToByteEncoder<Object> {
    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, ByteBuf out) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();

        byte[] payload = objectMapper.writeValueAsBytes(msg);
        int payloadSize = payload.length;

        ByteBuffer buffer = ByteBuffer.allocate(payloadSize + Message.PROTOCOL_HEADER_SIZE);

        buffer.putInt(payloadSize);
        buffer.put(payload);

        buffer.flip();

        out.writeBytes(buffer);
    }
}

class MessageDecoder extends ReplayingDecoder<Void> {
    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws IOException {
        long payloadSize = in.readUnsignedInt();

        if (payloadSize > Message.MAX_PAYLOAD_SIZE)
            return;

        byte[] buffer = new byte[(int) payloadSize];
        in.readBytes(buffer);

        Message message = new ObjectMapper().readValue(buffer, Message.class);

        if (message != null)
            out.add(message);
    }
}