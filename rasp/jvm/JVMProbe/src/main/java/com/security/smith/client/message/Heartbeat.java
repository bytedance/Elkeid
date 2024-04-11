package com.security.smith.client.message;

public class Heartbeat {
    private String filter;
    private String block;
    private String limit;
    private String patch;
    private String switchConfig;

    public String getFilter() {
        return filter;
    }

    public void setFilter(String filter) {
        this.filter = filter;
    }

    public String getBlock() {
        return block;
    }

    public void setBlock(String block) {
        this.block = block;
    }

    public String getLimit() {
        return limit;
    }

    public void setLimit(String limit) {
        this.limit = limit;
    }

    public String getPatch() {
        return patch;
    }

    public void setPatch(String patch) {
        this.patch = patch;
    }

    public String getSwitchConfig() {
        return switchConfig;
    }

    public void setSwitchConfig(String config) {
        this.switchConfig = config;
    }
}
