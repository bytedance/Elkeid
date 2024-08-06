package com.security.smith.client.message;

import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;

public class SwitchConfig {
    private String uuid;
    private Map<String, Boolean> switches;

    public String getUUID() {
        return uuid;
    }

    public void setUUID(String uuid) {
        this.uuid = uuid;
    }

    public Map<String, Boolean>  getSwitches() {
        return switches;
    }

    public void setSwitches(Map<String, Boolean>  switches) {
        this.switches = switches;
    }
}