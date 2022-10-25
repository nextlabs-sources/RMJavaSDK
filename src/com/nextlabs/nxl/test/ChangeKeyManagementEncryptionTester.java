package com.nextlabs.nxl.test;

import java.io.File;

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.exception.NXRTERROR;

public class ChangeKeyManagementEncryptionTester {

    public static void main(String[] args) throws NXRTERROR {
        RightsManager manager = new RightsManager(new File("C:/temp/config.properties"));
        try {
            manager.encrypt("C:/temp/output.txt", "C:/temp/output.txt.nxl", null, null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
        //		manager.cleanup();
        manager.cleanup();
        manager = new RightsManager(new File("C:/temp/config.properties"));
        try {
            manager.encrypt("C:/temp/output.txt", "C:/temp/output.txt.nxl", null, null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
        manager.cleanup();
    }
}
