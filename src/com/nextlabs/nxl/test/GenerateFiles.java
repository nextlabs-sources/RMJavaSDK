package com.nextlabs.nxl.test;

import com.nextlabs.nxl.util.EncryptionUtil;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Scanner;

public class GenerateFiles {

    public static void main(String[] args) throws IOException {
        System.out.println("Enter the file size to generate");
        Scanner sc = new Scanner(System.in);
        long contentLength = sc.nextLong();
        String content = " This is a nextlabs protected file ";
        byte[] contentBytes = content.getBytes();
        RandomAccessFile file = new RandomAccessFile("C:\\temp\\" + "test" + contentLength + "bytes.txt", "rw");
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
        System.out.println("Done");
    }
}
