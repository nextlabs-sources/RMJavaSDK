package com.nextlabs.nxl.test;

import com.nextlabs.nxl.util.DecryptionUtil;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;

public class FileTest {

    public static void main(String[] args) {
        RandomAccessFile f = null;
        RandomAccessFile f1 = null;
        long i = ((long)(2147479552 + 4096)) % Integer.MAX_VALUE;
        try {
            f = new RandomAccessFile("C:\\temp\\test5000000000bytes.txt", "r");
            f1 = new RandomAccessFile("C:\\temp\\test5000000000bytes1.txt", "r");
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
                    return;
                }
                iteration++;
            }
            System.out.println("Files are same.");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            try {
                f.close();
                f1.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
