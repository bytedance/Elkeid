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
    public static final int SCANCLASS = 10;             // scan on time
    public static final int SCANALLCLASS = 11;          // scan all
    public static final int CLASSFILTERSTART = 12;      // start to receive class filter rule
    public static final int CLASSFILTER = 13;           
    public static final int CLASSFILTEREND = 14;        // clas fiter rule end
    public static final int CLASSUPLOADSTART = 15;      // start to send class
    public static final int CLASSUPLOAD = 16;
    public static final int CLASSUPLOADEND = 17;        // end to send class
    public static final int SWITCHES = 18;    // switch
}