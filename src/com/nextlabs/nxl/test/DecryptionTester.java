package com.nextlabs.nxl.test;

import com.nextlabs.nxl.crypt.RightsManager;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class DecryptionTester {

    public static void main(String[] args) {
        File inputFolder = new File("C:\\Users\\psheoran\\Desktop\\Ruby\\NxlFiles");
        File outputFolder = new File("C:\\Users\\psheoran\\Desktop\\Ruby\\DecryptedFiles");
        File originalFolder = new File("C:\\Users\\psheoran\\Desktop\\Ruby\\OriginalFiles");
        File[] listOfFiles = inputFolder.listFiles();

        for (int i = 0; i < listOfFiles.length; i++) {
            if (listOfFiles[i].isFile() && listOfFiles[i].getName().endsWith(".nxl")) {
                System.out.println("Input File: " + listOfFiles[i].getName());
                String outputPath = outputFolder + "\\" + (listOfFiles[i].getName()).substring(0, listOfFiles[i].getName().length() - 4);
                String originalPath = originalFolder + "\\" + (listOfFiles[i].getName()).substring(0, listOfFiles[i].getName().length() - 4);
                System.out.println("Output File: " + outputPath);
                try {
                    RightsManager manager = new RightsManager(new File("C:/temp/config.properties"));
                    manager.decrypt(listOfFiles[i].getAbsolutePath(), null);
                    //handler.decrypt(outputPath);
                    matchFiles(originalPath, outputPath);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private static void matchFiles(String originalPath, String outputPath) throws FileNotFoundException {

        String originalContent = new Scanner(new File(originalPath)).useDelimiter("\\Z").next();
        System.out.println(originalContent);

        String outputContent = new Scanner(new File(outputPath)).useDelimiter("\\Z").next();
        System.out.println(outputContent);

        generateReport(originalContent, outputContent);
    }

    private static void generateReport(String originalContent,
        String outputContent) {
        System.out.println("Generating Report: ");

        if (originalContent.length() != outputContent.length()) {
            System.out.println("The length of files is different.");
        }
        if (!originalContent.equals(outputContent)) {
            System.out.println("The file contents are not same.");
        }
    }
}
