package com.security.smith.common;

import com.security.smith.log.SmithAgentLogger;

public class ParseParameter {
    public static boolean parseParameter(String Args,StringBuilder cmd,StringBuilder checksumStr,StringBuilder proberPath) {

        try {
            /**
             * attach;32 Byte Md5 Checksum;JavaProberPath;"
             */

            if(Args.length() < 7) {
                SmithAgentLogger.logger.warning("Invalid agent parameter - "+Args);
                return false;
            }

            String[] argX = Args.split(";") ;

            if(argX.length == 0) {
                SmithAgentLogger.logger.warning("Invalid agent parameter - "+Args);
                return false;
            }

            SmithAgentLogger.logger.info("agent parameter:"+Args);

            cmd.append(argX[0]);
            String xCmd = cmd.toString(); 
            if(xCmd.equals("attach")) {
                if(argX.length != 3) {
                    SmithAgentLogger.logger.warning("Invalid attach parameter - "+Args);
                    return false;
                }

                checksumStr.append(argX[1]);
                proberPath.append(argX[2]);

                return true;
            }
            else if(xCmd.equals("detach")) {
                if(argX.length != 1) {
                    return false;
                }

                return true;
            }

            SmithAgentLogger.logger.warning("Invalid agent parameter - "+Args);
        }
        catch(Exception e) {
            SmithAgentLogger.exception(e);
        }

        return false;
    }
}