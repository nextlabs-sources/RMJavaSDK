package com.nextlabs.nxl.test;

import com.nextlabs.nxl.crypt.RightsManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class APIEncryptionPerformanceThread implements Runnable {

    private String inputPath;
    private String outputPath;
    private int id;
    private RightsManager manager;

    public APIEncryptionPerformanceThread(RightsManager manager, String inputPath, String outputPath, int id) {
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
            HashMap<String, List<String>> tagMap = new HashMap();
            List<String> classification = new ArrayList<String>();
            //			classification.add("RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.RMS test automation framework consists of shell scripts that download latest RMS build from Hudson server, deploy it on the tomcat server and run the test classes. The shell script can be run on Windows using Cygwin and on Linux using the terminal.");
            classification.add("EAR-01");
            classification.add("ITAR-01");
            tagMap.put("EAR", classification);
            manager.encrypt(inputPath, outputPath, tagMap, null, null);
        } catch (Exception e) {
            System.out.println("Exception thrown by thread " + id);
            e.printStackTrace();
        }
    }
}