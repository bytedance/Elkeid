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
import com.security.smith.common.ProcessHelper;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import io.netty.handler.codec.ReplayingDecoder;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;

@JsonSerialize(using = ProtocolBufferSerializer.class)
@JsonDeserialize(using = ProtocolBufferDeserializer.class)
class ProtocolBuffer {
    static final int PROTOCOL_HEADER_SIZE = 4;
    static final int MAX_PAYLOAD_SIZE = 10240;

    Operate getOperate() {
        return operate;
    }

    public void setOperate(Operate operate) {
        this.operate = operate;
    }

    public JsonNode getData() {
        return data;
    }

    public void setData(JsonNode data) {
        this.data = data;
    }

    private Operate operate;
    private JsonNode data;
}

class ProtocolBufferSerializer extends StdSerializer<ProtocolBuffer> {
    static private final int pid;
    static private final String jvmVersion;
    static private final String probeVersion;

    static {
        pid = ProcessHelper.getCurrentPID();
        jvmVersion = ManagementFactory.getRuntimeMXBean().getSpecVersion();
        probeVersion = ProtocolBufferSerializer.class.getPackage().getImplementationVersion();
    }

    protected ProtocolBufferSerializer() {
        super(ProtocolBuffer.class);
    }

    protected ProtocolBufferSerializer(Class<ProtocolBuffer> t) {
        super(t);
    }

    @Override
    public void serialize(ProtocolBuffer value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeStartObject();

        gen.writeNumberField("pid", pid);
        gen.writeStringField("runtime", "JVM");
        gen.writeStringField("runtime_version", jvmVersion);
        gen.writeStringField("probe_version", probeVersion);
        gen.writeNumberField("time", Instant.now().getEpochSecond());

        gen.writeNumberField("message_type", value.getOperate().ordinal());
        gen.writeObjectField("data", value.getData());

        gen.writeEndObject();
    }
}

class ProtocolBufferDeserializer extends StdDeserializer<ProtocolBuffer> {
    protected ProtocolBufferDeserializer() {
        super(ProtocolBuffer.class);
    }

    protected ProtocolBufferDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public ProtocolBuffer deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode node = p.getCodec().readTree(p);

        ProtocolBuffer protocolBuffer = new ProtocolBuffer();

        protocolBuffer.setOperate(Operate.values()[node.get("message_type").asInt()]);
        protocolBuffer.setData(node.get("data"));

        return protocolBuffer;
    }
}

class ProtocolBufferEncoder extends MessageToByteEncoder<Object> {
    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, ByteBuf out) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();

        byte[] payload = objectMapper.writeValueAsBytes(msg);
        int payloadSize = payload.length;

        ByteBuffer buffer = ByteBuffer.allocate(payloadSize + ProtocolBuffer.PROTOCOL_HEADER_SIZE);

        buffer.putInt(payloadSize);
        buffer.put(payload);

        buffer.flip();

        out.writeBytes(buffer);
    }
}

class ProtocolBufferDecoder extends ReplayingDecoder<Void> {
    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws IOException {
        int payloadSize = in.readInt();

        if (payloadSize > ProtocolBuffer.MAX_PAYLOAD_SIZE)
            return;

        byte[] buffer = new byte[payloadSize];
        in.readBytes(buffer);

        ObjectMapper objectMapper = new ObjectMapper();

        ProtocolBuffer protocolBuffer = objectMapper.readValue(buffer, ProtocolBuffer.class);

        if (protocolBuffer != null)
            out.add(protocolBuffer);
    }
}