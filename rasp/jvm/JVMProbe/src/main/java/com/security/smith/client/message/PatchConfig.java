package com.security.smith.client.message;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.UUIDDeserializer;

import java.util.UUID;

public class PatchConfig {
    @JsonDeserialize(using = UUIDDeserializer.class)
    private UUID uuid;
    private Patch[] patches;

    public UUID getUUID() {
        return uuid;
    }

    public void setUUID(UUID uuid) {
        this.uuid = uuid;
    }

    public Patch[] getPatches() {
        return patches;
    }

    public void setPatches(Patch[] patches) {
        this.patches = patches;
    }
}
