package com.nextlabs.nxl.test;

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.pojos.NXLFile;
import com.nextlabs.nxl.util.DecryptionUtil;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.Scanner;

public class InMemoryDecryptionTester {

    public static void main(String[] args) throws Exception {
        String inputFilePath = "C:\\temp\\hi.txt.nxl";
        RightsManager manager = new RightsManager(new File("C:/temp/config.properties"));
        Scanner sc = new Scanner(System.in);
        //In memory Decryption
        long startTime = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
            System.out.println("Working on file " + i);
            /*File dir=new File("C:/temp/test"+i);
            if(!dir.exists()){
            	dir.mkdirs();
            }
            */NXLFile file = (NXLFile)manager.decrypt(inputFilePath, "C:/temp/output.txt.nxl");
            Runtime runtime = Runtime.getRuntime();
            // Run the garbage collector
            runtime.gc();
            // Run the garbage collector
            runtime.gc();
            // Calculate the used memory
            long memory = runtime.totalMemory() - runtime.freeMemory();
            File newFile = new File("C:/temp/output.txt");
            newFile.delete();
            System.out.println("Free memory: " + memory);
            System.out.println("File has been processed");
            System.out.println("------------------------------------------");
        }
        NXLFile file = (NXLFile)manager.decrypt("C:/temp/hi.txt.nxl", null);
        /*
        byte[][]decryptedData=((NewNxlFile)file).getDecryptedBytes();
        long bytesToRead=((NewNxlFile)file).getMetaData().getHeaders().getCryptoHeaders().getContentLength();
        RandomAccessFile newFile=new RandomAccessFile(new File("C:/temp/output.txt"),"rw");
        System.out.println("Completed In-memory decryption in "+(System.currentTimeMillis()-startTime)+" ms");
        long offset=0;
        for(int i=0;i<decryptedData.length;i++){
        	EncryptionUtil.writeBytes(newFile, decryptedData[i], offset);
        	offset+=decryptedData[i].length;
        }
        //Output File Decryption
        String outputPath="C:\\temp\\test2254857830bytesdecrypted.txt";
        DecryptionManager manager1=new DecryptionManager(inputFilePath, outputPath, "C:/temp/config.properties");
        manager1.decryptFile();
        manager1.close();
        System.out.println("Completed storage decryption in "+(System.currentTimeMillis()-startTime)+" ms");
        test(new RandomAccessFile(outputPath,"rw"),newFile);
        newFile.close();
        System.out.println("Files are same");
        System.out.println("Done");*/
        //manager.cleanup();
        /*byte[][] decryptedBytes=file.getDecryptedBytes();
        file.setDecryptedBytes(null);
        decryptedBytes=null;*/
        System.out.println("Total time taken is: " + (System.currentTimeMillis() - startTime));
    }

    public static boolean test(RandomAccessFile f, RandomAccessFile f1) {
        try {
            int blockSize = 4096;
            if (f.length() != f1.length()) {
                System.out.println("The file size is different");
                //return;
            }
            long left = f.length();
            int iteration = 0;
            while (left >= blockSize) {
                byte[] b = DecryptionUtil.readBytes(f, iteration * blockSize, blockSize);
                byte[] b1 = DecryptionUtil.readBytes(f, iteration * blockSize, blockSize);
                if (!Arrays.equals(b, b1)) {
                    System.out.println("Files are different at " + (iteration * blockSize) + " bytes");
                    return false;
                }
                iteration++;
            }
            System.out.println("Files are same.");
            return true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            try {
                f.close();
                f1.close();
                return false;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return true;
    }
}
