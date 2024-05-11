package com.security.smith.client;

public class Operate {
    public static final int EXIT = 0;
    public static final int HEARTBEAT = 1;
    public static final int TRACE = 2;
    public static final int CONFIG = 3;
    public static final int CONTROL = 4;
    public static final int DETECT = 5;
    public static final int FILTER = 6;
    public static final int BLOCK = 7;
    public static final int LIMIT = 8;
    public static final int PATCH = 9;
    public static final int SCANCLASS = 10;             // 实时扫描
    public static final int SCANALLCLASS = 11;          // 全量扫描
    public static final int CLASSFILTERSTART = 12;      // 开始清缓存
    public static final int CLASSFILTER = 13;           // 更新缓存
    public static final int CLASSFILTEREND = 14;        // 开始全量扫描
    public static final int CLASSUPLOADSTART = 15;      // 开始上传class
    public static final int CLASSUPLOAD = 16;
    public static final int CLASSUPLOADEND = 17;        // 结束上传class
}