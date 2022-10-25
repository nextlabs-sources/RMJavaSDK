package com.nextlabs.nxl.crypt;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class AESEncryptionUtil {

    private static SecureRandom randomGenerator = new SecureRandom();

    public static byte[] processData(byte[] key, byte[] originalData, int size, long ivec, int mode) {
        byte[] dataArr = new byte[size];
        int iteration = 0;
        while (0 != size) {
            int cbclen = Math.min(512, size);
            ByteBuffer bb = ByteBuffer.allocate(8);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putLong(0, ivec);
            byte[] blockArray = bb.array();
            byte[] ivArray = new byte[16];
            System.arraycopy(blockArray, 0, ivArray, 0, 8);
            byte[] cbcContent = new byte[cbclen];
            System.arraycopy(originalData, iteration * 512, cbcContent, 0, cbclen);
            byte[] processedData = getProcessedContent(cbcContent, key, ivArray, mode);
            System.arraycopy(processedData, 0, dataArr, iteration * 512, cbclen);
            iteration++;
            ivec += cbclen;
            size -= cbclen;
        }
        return dataArr;
    }

    public static byte[] getProcessedContent(byte[] inputContent, byte[] passPhraseArr, byte[] IV, int mode) {
        try {
            byte[] processedData = doFinal(passPhraseArr, IV, inputContent, mode);
            return processedData;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] doFinal(byte[] passPhraseArr, byte[] IV, byte[] inputContent, int mode) throws Exception {
        SecretKeySpec sessionKey = new SecretKeySpec(passPhraseArr, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(mode, sessionKey, new IvParameterSpec(IV));
        byte[] processedData = cipher.doFinal(inputContent);
        return processedData;
    }

    public static String hex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    public static byte[] hex(String str) {
        return DatatypeConverter.parseHexBinary(str);
    }

    public static synchronized byte[] generateNewKey(byte[] randomKey) {
        randomGenerator.nextBytes(randomKey);
        return randomKey;
    }

}
