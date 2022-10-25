package com.nextlabs.nxl.sharedutil;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class EncryptionUtil {

    private static final int PAGE_SIZE = 128;
    private final byte[] encryptionKey = { 83, -114, 30, 14, -64, 97, 82, 36, 20, 56, 115, -63, 89, 50, -95, -106, -18,
        120, 8, 99, 99,
        47, 63, -15, 96, -43, -91, -118, 85, -50, 15, 44 };

    private byte[] processData(byte[] originalData, int size, long ivec, int mode) {
        byte[] dataArr = new byte[size];
        int iteration = 0;
        while (0 != size) {
            int cbclen = Math.min(32, size);
            ByteBuffer bb = ByteBuffer.allocate(8);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putLong(0, ivec);
            byte[] blockArray = bb.array();
            byte[] ivArray = new byte[16];
            System.arraycopy(blockArray, 0, ivArray, 0, 8);
            byte[] cbcContent = new byte[cbclen];
            System.arraycopy(originalData, iteration * 32, cbcContent, 0, cbclen);
            byte[] processedData = getProcessedContent(cbcContent, encryptionKey, ivArray, mode);
            System.arraycopy(processedData, 0, dataArr, iteration * 32, cbclen);
            iteration++;
            ivec += cbclen;
            size -= cbclen;
        }
        return dataArr;
    }

    private byte[] getProcessedContent(byte[] inputContent, byte[] passPhraseArr, byte[] IV, int mode) {
        try {
            byte[] processedData = doFinal(passPhraseArr, IV, inputContent, mode);
            return processedData;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] doFinal(byte[] passPhraseArr, byte[] IV, byte[] inputContent, int mode) throws Exception {
        SecretKeySpec sessionKey = new SecretKeySpec(passPhraseArr, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(mode, sessionKey, new IvParameterSpec(IV));
        byte[] processedData = cipher.doFinal(inputContent);
        return processedData;
    }

    private byte[] getProcessedContent(byte[] contentBytes, int mode) {
        long iterationCount = 0;
        int blockSize = PAGE_SIZE;
        long paddedContentLength = roundToSize(contentBytes.length, blockSize);
        long bytesToRead = paddedContentLength;
        long ivec = 0;
        byte[] dataChunk = null;
        while (bytesToRead >= blockSize) {
            dataChunk = new byte[blockSize];
            System.arraycopy(contentBytes, (int)iterationCount * blockSize, dataChunk, 0, contentBytes.length);
            byte[] encryptedChunk = processData(dataChunk, blockSize, ivec, mode);
            System.arraycopy(encryptedChunk, 0, dataChunk, (int)iterationCount * blockSize, encryptedChunk.length);
            bytesToRead -= blockSize;
            ivec += blockSize;
            iterationCount++;
        }
        return dataChunk;
    }

    private int roundToSize(int length, int alignment) {
        return (length + ((alignment) - 1)) & ~((alignment) - 1);
    }

    public static void main(String[] args) throws IOException {
        int mode = 0;
        EncryptionUtil util = new EncryptionUtil();
        if (!util.validate(args)) {
            return;
        }
        String inputString = args[1];
        String modeString = args[0].trim();
        if (modeString.trim().equals("encrypt")) {
            mode = 1;
        } else if (modeString.trim().equals("decrypt")) {
            mode = 2;
        } else {
            System.out.println("\nError: Invalid operation mode provided");
            util.printUsage();
            return;
        }
        if (mode == Cipher.ENCRYPT_MODE) {
            String encryptedStr = util.encrypt(inputString);
            System.out.println("Encrypted content:" + encryptedStr);

        }
        if (mode == Cipher.DECRYPT_MODE) {
            String decryptedStr = util.decrypt(inputString);
            System.out.println("Decrypted content:" + decryptedStr);
        }
    }

    private boolean validate(String[] args) {
        if (args.length == 0) {
            printUsage();
            return false;
        } else if (args.length != 2) {
            System.out.println("\nERROR: Invalid number of arguments provided.");
            printUsage();
            return false;
        }
        return true;
    }

    private void printUsage() {
        System.out.println("\nEncryptionUtil");
        System.out.println("\nDescription");
        System.out.println("    This utility encrypts or decrypts a given string. It can be used to encrypt passwords.");
        System.out.println("\nUSAGE");
        // OS check
        char separator = File.pathSeparatorChar;
        StringBuilder builder = new StringBuilder(140);
        builder.append("    java -cp .");
        builder.append(separator);
        builder.append("RMEncryptionUtil.jar");
        builder.append(separator);
        builder.append("commons-codec-1.10.jar ");
        builder.append(EncryptionUtil.class.getName());
        builder.append(" [encrypt|decrypt] [input_string]");
        System.out.println(builder.toString());
        System.out.println("\nOPTIONS");
        System.out.println("    encrypt");
        System.out.println("        Encrypt the input string");
        System.out.println("    decrypt");
        System.out.println("        Decrypt the input string");
        System.out.println("    input_string");
        System.out.println(
                "        String to be encrypted or decrypted. If the string contains spaces, wrap the string in double quotes(\"\")");
        System.out.println("\nExample");
        builder = new StringBuilder(160);
        builder.append("    java -cp .");
        builder.append(separator);
        builder.append("RMEncryptionUtil.jar");
        builder.append(separator);
        builder.append("commons-codec-1.10.jar ");
        builder.append(EncryptionUtil.class.getName());
        builder.append(" encrypt \"Lorem Ipsum\"");
        System.out.println(builder.toString());
    }

    public String decrypt(String inputString) {
        EncryptionUtil manager = new EncryptionUtil();
        byte[] processedContent = manager.getProcessedContent(Base64.decodeBase64(inputString.getBytes()),
                Cipher.DECRYPT_MODE);
        String str = new String(processedContent).split("\0")[0];
        return str;
    }

    public String encrypt(String inputString) {
        EncryptionUtil manager = new EncryptionUtil();
        byte[] processedContent = manager.getProcessedContent(inputString.getBytes(), Cipher.ENCRYPT_MODE);
        byte[] encode = Base64.encodeBase64(processedContent);
        String base64 = new String(encode);
        return base64;
    }
}
