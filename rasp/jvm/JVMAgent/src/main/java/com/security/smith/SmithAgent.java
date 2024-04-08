package com.security.smith;

import com.security.smith.log.SmithLogger;

import io.netty.util.internal.SystemPropertyUtil;

import java.lang.instrument.Instrumentation;

public class SmithAgent {
     private static boolean parseParameter(String Args,StringBuilder cmd,StringBuilder checksumStr,StringBuilder proberPath) {

        try {
            /**
             * attach;32 Byte Md5 Checksum;JavaProberPath;"
             */

            if(Args.length() < 7) {
                SmithLogger.logger.warning("Invalid agent parameter - "+Args);
                return false;
            }

            String[] argX = Args.split(";") ;

            if(argX.length == 0) {
                SmithLogger.logger.warning("Invalid agent parameter - "+Args);
                return false;
            }

            SmithLogger.logger.info("agent parameter:"+Args);

            cmd.append(argX[0]);
            String xCmd = cmd.toString(); 
            if(xCmd.equals("attach")) {
                if(argX.length != 3) {
                    SmithLogger.logger.warning("Invalid attach parameter - "+Args);
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

            SmithLogger.logger.warning("Invalid agent parameter - "+Args);
        }
        catch(Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    public static void premain(String agentArgs, Instrumentation inst) {
        agentmain(agentArgs, inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        String agent = System.getProperty("rasp.agent");

        System.out.println("agentArgs:"+agentArgs);

        StringBuilder cmd_sb = new StringBuilder();
        StringBuilder checksumStr_sb = new StringBuilder();
        StringBuilder proberPath_sb = new StringBuilder();
        String cmd = "";
        String checksumStr = "";
        String proberPath = "";

        if(parseParameter(agentArgs,cmd_sb,checksumStr_sb,proberPath_sb)) {
            cmd = cmd_sb.toString();
            checksumStr = checksumStr_sb.toString();
            proberPath = proberPath_sb.toString();

            System.out.println("cmd:" + cmd);
            System.out.println("checksumStr:" + checksumStr);
            System.out.println("proberPath:" + proberPath); 
            System.out.println("parse parseParameter success");
        }
        else {
            System.out.println("parse parameter fail");
            return ;
        }

        

        if (agent != null) {
            SmithLogger.logger.info("agent running");
            return;
        }

        System.setProperty("rasp.agent", "smith");
    }
}
