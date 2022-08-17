package com.security.smith.client.message;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.UUIDDeserializer;

import java.util.UUID;

public class FilterConfig {
    @JsonDeserialize(using = UUIDDeserializer.class)
    private UUID uuid;
    private Filter[] filters;

    public UUID getUUID() {
        return uuid;
    }

    public void setUUID(UUID uuid) {
        this.uuid = uuid;
    }

    public Filter[] getFilters() {
        return filters;
    }

    public void setFilters(Filter[] filters) {
        this.filters = filters;
    }
}
