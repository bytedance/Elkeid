package com.security.smith.type;

public class SmithMethod {
    private int id;
    private String name;
    private String desc;
    private boolean block;
    private String preHook;
    private String postHook;
    private String exceptionHook;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }

    public boolean isBlock() {
        return block;
    }

    public void setBlock(boolean block) {
        this.block = block;
    }

    public String getPreHook() {
        return preHook;
    }

    public void setPreHook(String preHook) {
        this.preHook = preHook;
    }

    public String getPostHook() {
        return postHook;
    }

    public void setPostHook(String postHook) {
        this.postHook = postHook;
    }

    public String getExceptionHook() {
        return exceptionHook;
    }

    public void setExceptionHook(String exceptionHook) {
        this.exceptionHook = exceptionHook;
    }
}
