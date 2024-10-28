package com.security.smith.log;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.security.smith.common.ProcessHelper;

public class AttachInfo {
    public  static void  info() {

        try {
            Path path = Paths.get("/proc/" + ProcessHelper.getCurrentPID() + "/cwd");
            String cwd = Files.readSymbolicLink(path).toString();

            File file = new File(cwd);

            if (file.exists()) {

                file = new File(cwd + "/0_your_service_has_been_protected_by_elkeid_rasp.log");
                if (!file.exists()) {
                    if (file.createNewFile()) {

                        FileWriter writer = new FileWriter(file);
                        writer.write("Your Java Service Will Be Protected By RASP");
                        writer.close();
                    }
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}