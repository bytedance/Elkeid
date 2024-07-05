package com.security.smith.common;

import com.security.smith.log.SmithLogger;

public class SmithTools {
    enum WebMiddlewareType {
        WMT_GLASSFISH,
        WMT_UNKNOW
    };

    private static WebMiddlewareType web_mid_type = WebMiddlewareType.WMT_UNKNOW;
    private static int major_version = 0;
    private static int minor_version = 0;

    private static boolean getGlassfishInfo() {
        String serverInfo = System.getProperty("glassfish.version");
        if(serverInfo != null && !serverInfo.isEmpty()) {
            web_mid_type = WebMiddlewareType.WMT_GLASSFISH;

            SmithLogger.logger.info("Web Middleware Info:"+serverInfo);

            String[] parts = serverInfo.split(" ");
            if(parts.length > 0) {

                //
                // version > 5
                //

                if(parts[0].equals("Eclipse")) {
                    if(!parts[1].equals("GlassFish")) {
                        return false;
                    }

                    String[] versionParts = parts[2].split("\\.");
            
                    major_version = Integer.parseInt(versionParts[0]);
                    minor_version = Integer.parseInt(versionParts[1]);

                    return true;
                } else if(parts[0].equals("GlassFish")){
                    if(parts.length <7)  {
                        return false;
                    }

                    String[] versionParts = parts[6].split("\\.");
            
                    major_version = Integer.parseInt(versionParts[0]);
                    minor_version = Integer.parseInt(versionParts[1]);

                    return true;
                }
            } 
        }

        return false;
    }

    public static void init() {
        try {
            if(getGlassfishInfo()) {
                return ;
            }
        }
        catch(Exception e) {
            SmithLogger.exception(e);
        }
    }

    public static int getMajorVersion() {
        return major_version;
    }

    public static int getMinorVersion() {
        return minor_version;
    }

    public static boolean isGlassfish() {
        return web_mid_type == WebMiddlewareType.WMT_GLASSFISH;
    }
}
