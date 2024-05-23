package com.security.smith.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.handler.codec.ReplayingDecoder;
import io.netty.channel.ChannelHandlerContext;
import io.netty.buffer.ByteBuf;
import java.util.List;
import java.io.IOException;

public class MessageDecoder extends ReplayingDecoder<Void> {
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