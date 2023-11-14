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
    CLASSDUMP,
    CLASSDUMPEND,
    SCANCLASS,          // 实时扫描
    SCANALLCLASS,       // 全量扫描
    CLASSFILTERSTART,   // 开始清缓存
    CLASSFILTER,           // 更新缓存
    CLASSFILTEREND,        // 开始全量扫描
}