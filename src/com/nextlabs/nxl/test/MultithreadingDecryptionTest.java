package com.nextlabs.nxl.test;

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.exception.NXRTERROR;

import java.io.File;
import java.util.StringTokenizer;

public class MultithreadingDecryptionTest {

    public static void main(String[] args) throws NXRTERROR {
        String inputDirectoryPath = "C:\\Users\\psheoran\\Desktop\\Ruby\\NxlFiles";
        String outputDirectory = "C:\\Users\\psheoran\\Desktop\\Ruby\\DecryptedFiles";
        File inputDirectory = new File(inputDirectoryPath);
        int id = 1;
        RightsManager manager = new RightsManager(new File("C:/temp/config.properties"));
        for (File file : inputDirectory.listFiles()) {
            try {
                System.out.println(file.getAbsolutePath());
                String name = "";
                StringTokenizer str = new StringTokenizer(file.getAbsolutePath(), "\\ /");
                while (str.hasMoreTokens()) {
                    name = str.nextToken();
                }
                name = name.substring(0, name.length() - 4);
                Thread t = new Thread(new APIDecryptionPerformanceThread(manager, file.getAbsolutePath(), outputDirectory + "\\" + name, id++));
                t.start();
                t.join();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        manager.cleanup();
        System.out.println("All threads created");
    }
}
