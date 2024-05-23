package com.security.smith.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.handler.codec.MessageToByteEncoder;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import java.nio.ByteBuffer;

public class MessageEncoder extends MessageToByteEncoder<Object> {
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