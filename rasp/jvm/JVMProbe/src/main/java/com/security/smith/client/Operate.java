package com.security.smith.client;

public enum Operate {
    EXIT,
    HEARTBEAT,
    TRACE,
    CONFIG,
    CONTROL,
    DETECT,
    FILTER,
    BLOCK,
    LIMIT,
    PATCH,
    SCANCLASS,             // 实时扫描
    SCANALLCLASS,          // 全量扫描
    CLASSFILTERSTART,      // 开始清缓存
    CLASSFILTER,           // 更新缓存
    CLASSFILTEREND,        // 开始全量扫描
    CLASSUPLOADSTART,      // 开始上传class
    CLASSUPLOAD,
    CLASSUPLOADEND,        // 结束上传class
}