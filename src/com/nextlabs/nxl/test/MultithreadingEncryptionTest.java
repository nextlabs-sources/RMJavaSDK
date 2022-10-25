package com.nextlabs.nxl.test;

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.exception.NXRTERROR;

import java.io.File;
import java.util.StringTokenizer;

public class MultithreadingEncryptionTest {

    public static void main(String[] args) throws NXRTERROR {
        String inputDirectoryPath = "C:\\Users\\psheoran\\Desktop\\Ruby\\OriginalFiles";
        String outputDirectory = "C:\\Users\\psheoran\\Desktop\\Ruby\\NxlFiles";
        File inputDirectory = new File(inputDirectoryPath);
        int id = 1;
        RightsManager manager = new RightsManager(new File("C:/temp/config.properties"));
        for (File file : inputDirectory.listFiles()) {
            try {
                StringTokenizer nameTokenizer = new StringTokenizer(file.getAbsolutePath(), "/ \\");
                String name = "";
                while (nameTokenizer.hasMoreTokens()) {
                    name = nameTokenizer.nextToken();
                }
                System.out.println(file.getAbsolutePath());
                Thread t = new Thread(new APIEncryptionPerformanceThread(manager, file.getAbsolutePath(), outputDirectory + "/" + name + ".nxl", id++));
                t.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("All threads created");
    }
}
