package com.security.smith.client;

import java.lang.reflect.Type;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import io.netty.buffer.ByteBuf;
import java.nio.ByteBuffer;
import com.security.smith.client.MessageSerializer;
import com.security.smith.client.MessageDeserializer;

public class MessageEncoder extends MessageToByteEncoder<Object> {
    private static Gson gson = null;

    public static void delInstance() {
        gson = null;
    }

    public static void initInstance() {
        gson = new GsonBuilder()
            .registerTypeAdapter(Message.class, new MessageSerializer())
            .registerTypeAdapter(Message.class, new MessageDeserializer())
            .create();
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, ByteBuf out) {
        try {
            byte[] payload = gson.toJson(msg).getBytes();
            int payloadSize = payload.length;

            ByteBuffer buffer = ByteBuffer.allocate(payloadSize + Message.PROTOCOL_HEADER_SIZE);
            buffer.putInt(payloadSize);
            buffer.put(payload);
            buffer.flip();

            out.writeBytes(buffer);
        } 
        catch(Throwable e) {
            e.printStackTrace();
        }
       
    }
}
