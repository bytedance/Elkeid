package com.security.smith.rulemgr;

public class StackItem {
    //public Boolean isHash;
    public long hashcode;
    public long length;
    public String stackinfo;

    // public void setIsHash(Boolean isHash) {
    //     this.isHash = isHash;
    // }

    // public Boolean getIsHash() {
    //     return this.isHash;
    // }

    public void setHashcode(Long hashcode) {
        this.hashcode = hashcode;
    }

    public Long getHashcode() {
        return this.hashcode;
    }

    public void setLength(long length) {
        this.length = length;
    }

    public long getLength() {
        return this.length;
    }

    public void setStackinfo(String stackinfo) {
        this.stackinfo = stackinfo;
    }

    public String getStackinfo() {
        return this.stackinfo;
    }

    public String toString() {
        return  "hashcode:" + this.hashcode + " length:" + this.length + " stackinfo:" + this.stackinfo;
    }
}