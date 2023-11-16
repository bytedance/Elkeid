package com.security.smith.client.message;

public class LimitConfig {
    private String uuid;
    private Limit[] limits;

    public String getUUID() {
        return uuid;
    }

    public void setUUID(String uuid) {
        this.uuid = uuid;
    }

    public Limit[] getLimits() {
        return limits;
    }

    public void setLimits(Limit[] limits) {
        this.limits = limits;
    }
}
