package com.security.smith.client.message;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.UUIDDeserializer;

import java.util.UUID;

public class LimitConfig {
    @JsonDeserialize(using = UUIDDeserializer.class)
    private UUID uuid;
    private Limit[] limits;

    public UUID getUUID() {
        return uuid;
    }

    public void setUUID(UUID uuid) {
        this.uuid = uuid;
    }

    public Limit[] getLimits() {
        return limits;
    }

    public void setLimits(Limit[] limits) {
        this.limits = limits;
    }
}
