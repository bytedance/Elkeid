package com.security.smith.client;

import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.core.JsonGenerator;
import java.lang.management.ManagementFactory;
import java.io.IOException;
import java.time.Instant;
import com.security.smith.common.ProcessHelper;

public class MessageSerializer extends StdSerializer<Message> {
    static private final int pid;
    static private final String jvmVersion;
    static private String probeVersion;

    static {
        pid = ProcessHelper.getCurrentPID();
        jvmVersion = ManagementFactory.getRuntimeMXBean().getSpecVersion();
    } 

    public static void setProbeVersion(String probeVer) {
        probeVersion = probeVer;
    }

    public static void delInstance() {
        probeVersion = null;
    }

    protected MessageSerializer() {
        super(Message.class);
    }

    protected MessageSerializer(Class<Message> t) {
        super(t);
    }

    @Override
    public void serialize(Message value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeStartObject();
        gen.writeNumberField("message_type", value.getOperate());

        gen.writeNumberField("pid", pid);
        gen.writeStringField("runtime", "JVM");
        gen.writeStringField("runtime_version", jvmVersion);
        gen.writeStringField("probe_version", probeVersion);
        gen.writeNumberField("time", Instant.now().getEpochSecond());

        gen.writeObjectField("data", value.getData());

        gen.writeEndObject();
    }
}
