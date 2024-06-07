
package com.security.smith.client;

import java.lang.reflect.Type;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ReplayingDecoder;
import io.netty.buffer.ByteBuf;
import com.security.smith.client.MessageSerializer;
import com.security.smith.client.MessageDeserializer;

import java.io.IOException;
import java.util.List;

public class MessageDecoder extends ReplayingDecoder<Void> {
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
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws IOException {
        try {
            long payloadSize = in.readUnsignedInt();
            if (payloadSize > Message.MAX_PAYLOAD_SIZE)
                return;

            byte[] buffer = new byte[(int) payloadSize];
            in.readBytes(buffer);

            String msg = new String(buffer);
            Message message = gson.fromJson(msg,Message.class);
            if (message != null)
                out.add(message);
        }
        catch(Throwable e) {
            e.printStackTrace();
        }
        
    }
}