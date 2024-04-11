package com.security.smith.client.message;

public class SwitchConfig {
    private String uuid;
    private Integer enableSwitch;
    private DisableHooks[] disableHooks;

    public String getUUID() {
        return uuid;
    }

    public void setUUID(String uuid) {
        this.uuid = uuid;
    }

    public Integer getEnableSwitch() {
        return enableSwitch;
    }

    public void setEnableSwitch(Integer enableSwitch) {
        this.enableSwitch = enableSwitch;
    }

    public DisableHooks[] getDisableHooks() {
        return disableHooks;
    }

    public void setDisableHooks(DisableHooks[] disableHooks) {
        this.disableHooks = disableHooks;
    }
}
