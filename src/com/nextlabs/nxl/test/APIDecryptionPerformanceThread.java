package com.nextlabs.nxl.test;

import com.nextlabs.nxl.crypt.RightsManager;

public class APIDecryptionPerformanceThread implements Runnable {

    private String inputPath;
    private String outputPath;
    private int id;
    private RightsManager manager;

    public APIDecryptionPerformanceThread(RightsManager manager, String inputPath, String outputPath, int id) {
        this.inputPath = inputPath;
        this.outputPath = outputPath;
        this.id = id;
        this.manager = manager;
        System.out.println("Starting thread with id " + id);
    }

    @Override
    public void run() {
        System.out.println("Ending Thread with id " + id);
        try {
            manager.decrypt(inputPath, outputPath);
        } catch (Exception e) {
            System.out.println("Exception thrown by thread " + id);
            e.printStackTrace();
        }
    }
}
