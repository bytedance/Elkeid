package com.security.smith.client.message;

public class BlockConfig {
    private String uuid;
    private Block[] blocks;

    public String getUUID() {
        return uuid;
    }

    public void setUUID(String uuid) {
        this.uuid = uuid;
    }

    public Block[] getBlocks() {
        return blocks;
    }

    public void setBlocks(Block[] blocks) {
        this.blocks = blocks;
    }

    public void removeAll() {
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = null;
        }
        blocks = null;
    }
}