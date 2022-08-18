package com.security.smith.client.message;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.UUIDSerializer;

import java.util.UUID;

public class Heartbeat {
    @JsonSerialize(using = UUIDSerializer.class)
    private UUID filter;

    @JsonSerialize(using = UUIDSerializer.class)
    private UUID block;

    @JsonSerialize(using = UUIDSerializer.class)
    private UUID limit;

    @JsonSerialize(using = UUIDSerializer.class)
    private UUID patch;

    public UUID getFilter() {
        return filter;
    }

    public void setFilter(UUID filter) {
        this.filter = filter;
    }

    public UUID getBlock() {
        return block;
    }

    public void setBlock(UUID block) {
        this.block = block;
    }

    public UUID getLimit() {
        return limit;
    }

    public void setLimit(UUID limit) {
        this.limit = limit;
    }

    public UUID getPatch() {
        return patch;
    }

    public void setPatch(UUID patch) {
        this.patch = patch;
    }
}
