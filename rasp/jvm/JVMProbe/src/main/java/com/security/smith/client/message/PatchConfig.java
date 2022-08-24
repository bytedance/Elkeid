package com.security.smith.client.message;

public class PatchConfig {
    private String uuid;
    private Patch[] patches;

    public String getUUID() {
        return uuid;
    }

    public void setUUID(String uuid) {
        this.uuid = uuid;
    }

    public Patch[] getPatches() {
        return patches;
    }

    public void setPatches(Patch[] patches) {
        this.patches = patches;
    }
}
