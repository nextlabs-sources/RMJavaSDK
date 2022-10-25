package com.nextlabs.nxl.test;

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.pojos.NXLFile;
import com.nextlabs.nxl.util.EncryptionUtil;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PerformanceTestingNumbers {

    public static void main(String[] args) throws Exception {
        long[] fileSizeArr = { 0, 10, 100, 1000, 10000, 100000, 1024 * 1024L, 10 * 1024 * 1024L, 50 * 1024 * 1024L,
            100 * 1024 * 1024L, 500 * 1024 * 1024L, 1024 * 1024 * 1024L, 2 * 1024 * 1024 * 1024L,
            3 * 1024 * 1024 * 1024L, 4 * 1024 * 1024 * 1024L, 5 * 1024 * 1024 * 1024L, 6 * 1024 * 1024 * 1024L,
            7 * 1024 * 1024 * 1024L, 8 * 1024 * 1024 * 1024L, 9 * 1024 * 1024 * 1024L, 10 * 1024 * 1024 * 1024L,
            15 * 1024 * 1024 * 1024L };
        int maxCount = 5;
        for (int i = 0; i < fileSizeArr.length; i++) {
            int counter = 0;
            //Generate file
            long creationTime = System.currentTimeMillis();
            String inputPath = generateFile(fileSizeArr[i]);
            System.out.println("The time taken to create the file is: " + (System.currentTimeMillis() - creationTime));
            System.out.println("Time taken for encrypting " + inputPath + " is: ");
            long[] encryptionTimes = new long[maxCount];
            long[] decryptionTimes = new long[maxCount];
            while (counter < maxCount) {
                //Encrypt file
                RightsManager manager = new RightsManager(new File("C:/temp/config.properties"));
                long encryptTime = System.currentTimeMillis();
                //					System.out.println(System.currentTimeMillis());
                HashMap<String, String> map = new HashMap<String, String>();
                map.put("Department", "Training");
                map.put("Course", "Conductor Etch Chamber Hardware Evolution");
                map.put("Program", "PR-02");
                map.put("EAR", "EAR-Classify");
                manager.encrypt(inputPath, inputPath + ".nxl", null, null, null);
                //					System.out.println(System.currentTimeMillis());
                long timeToEncrypt = System.currentTimeMillis() - encryptTime;
                encryptionTimes[counter] = timeToEncrypt;
                //					System.out.print((System.currentTimeMillis()-encryptTime) +" ms   ");
                long decryptTime = System.currentTimeMillis();
                NXLFile nxlFile = manager.decrypt(inputPath + ".nxl", inputPath);
                long timeToDecrypt = System.currentTimeMillis() - decryptTime;
                decryptionTimes[counter] = timeToDecrypt;
                Map<String, List<String>> tags = nxlFile.getMetaData().getTags();
                counter++;
            }

            File originalFile = new File(inputPath);
            originalFile.delete();
            File outputFile = new File(inputPath + ".nxl");
            outputFile.delete();

            System.out.println("Details for file of size " + fileSizeArr[i] + " are as follows");
            System.out.print("Encryption times : ");

            long avgEncTime = 0;
            for (int j = 0; j < maxCount; j++) {
                System.out.print(encryptionTimes[j] + " ms  ,  ");
                avgEncTime += encryptionTimes[j];
            }
            System.out.print("\n");
            System.out.println("Average encryption time = " + avgEncTime / 5 + " ms");

            System.out.print("Decryption times : ");
            long avgDecTime = 0;
            for (int j = 0; j < maxCount; j++) {
                System.out.print(decryptionTimes[j] + " ms  ,  ");
                avgDecTime += decryptionTimes[j];
            }
            System.out.print("\n");
            System.out.println("Average decryption time = " + avgDecTime / 5 + " ms");
            System.out.println("-------------------------------------------------------------\n");
        }
    }

    private static String generateFile(long contentLength) throws FileNotFoundException,
            IOException {
        String content = " This is a nextlabs protected file ";
        byte[] contentBytes = content.getBytes();
        String filePath = "C:/temp/" + "test" + contentLength + "bytes.txt";
        RandomAccessFile file = new RandomAccessFile(filePath, "rw");
        file.setLength(contentLength);
        //long iterations= contentLength/content.length();
        long remainder = contentLength % content.length();
        long left = contentLength;
        long iterations = 0;
        while (left > content.length()) {
            EncryptionUtil.writeBytes(file, contentBytes, iterations * content.length());
            iterations++;
            left -= content.length();
        }
        byte[] remainderArr = new byte[(int)remainder];
        System.arraycopy(contentBytes, 0, remainderArr, 0, (int)remainder);
        EncryptionUtil.writeBytes(file, remainderArr, iterations * content.length());
        file.close();
        return filePath;
    }
}
