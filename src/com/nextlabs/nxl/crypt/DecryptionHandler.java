package com.nextlabs.nxl.crypt;

import com.nextlabs.nxl.pojos.BasicHeaders;
import com.nextlabs.nxl.pojos.CryptoHeaders;
import com.nextlabs.nxl.pojos.NXLFile;
import com.nextlabs.nxl.util.DecryptionUtil;
import com.nextlabs.nxl.util.EncryptionUtil;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import javax.crypto.Cipher;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class DecryptionHandler extends AbstractDecryptionHandler {

    private byte[][] decryptedFileBytes = null;

    private NXLFile unwrappedFile = null;

    private static Logger logger = LoggerFactory.getLogger("DecryptionHandler");

    public NXLFile parseContent(RandomAccessFile nxlFile, String tenantId) throws Exception {
        readMeta(nxlFile);
        if (decryptedFileBytes != null && unwrappedFile != null) {
            return unwrappedFile;
        }
        if (nxlHeaders == null) {
            readHeaders(nxlFile, tenantId);
            validateHeaderInfo();
        }
        decryptedFileBytes = decryptFileContent(nxlFile);
        createUnwrappedFile();
        return unwrappedFile;
    }

    public NXLFile parseContent(RandomAccessFile nxlFile, String outputPath, String tenantId) throws Exception {
        RandomAccessFile outputRandomFile = null;
        try {
            readMeta(nxlFile);
            File outputFile = new File(outputPath);
            outputRandomFile = new RandomAccessFile(outputFile, "rw");
            if (nxlHeaders == null) {
                readHeaders(nxlFile, tenantId);
                validateHeaderInfo();
            }
            decryptAndWriteFileContent(nxlFile, outputRandomFile);
            createUnwrappedFile();
            return unwrappedFile;
        } finally {
            IOUtils.closeQuietly(outputRandomFile);
        }
    }

    private void createUnwrappedFile() {
        unwrappedFile = new NXLFile();
        unwrappedFile.setMetaData(metaData);
        unwrappedFile.setDecryptedBytes(decryptedFileBytes);
    }

    private void decryptAndWriteFileContent(RandomAccessFile file, RandomAccessFile outputFile) throws Exception {
        CryptoHeaders cryptoHeaders = nxlHeaders.getCryptoHeaders();
        BasicHeaders basicHeaders = nxlHeaders.getBasicHeaders();
        long iterationCount = 0;
        int blockSize = DecryptionUtil.NXL_PAGE_SIZE;
        long bytesToRead = cryptoHeaders.getContentLength();
        long startIndex = basicHeaders.getPointerOfContent();
        byte[] primaryKey = getCEK(cryptoHeaders);
        long ivec = 0;
        while (bytesToRead >= blockSize) {
            long startRead = System.currentTimeMillis();
            byte[] encryptedChunk = DecryptionUtil.readBytes(file, startIndex, blockSize);
            readTime += System.currentTimeMillis() - startRead;
            byte[] decryptedChunk = AESEncryptionUtil.processData(primaryKey, encryptedChunk, blockSize, ivec, Cipher.DECRYPT_MODE);
            long startWrite = System.currentTimeMillis();
            EncryptionUtil.writeBytes(outputFile, decryptedChunk, iterationCount * blockSize);
            writeTime += System.currentTimeMillis() - startWrite;
            bytesToRead -= blockSize;
            ivec += blockSize;
            iterationCount++;
            startIndex += blockSize;
        }
        if (bytesToRead > 0) {
            byte[] encryptedChunk = DecryptionUtil.readBytes(file, startIndex, blockSize);
            byte[] decryptedChunk = AESEncryptionUtil.processData(primaryKey, encryptedChunk, blockSize, ivec, Cipher.DECRYPT_MODE);
            byte[] unpaddedArray = new byte[(int)bytesToRead];
            System.arraycopy(decryptedChunk, 0, unpaddedArray, 0, (int)bytesToRead);
            EncryptionUtil.writeBytes(outputFile, unpaddedArray, iterationCount * blockSize);
            bytesToRead = 0;
        }
        
    }

    private byte[][] decryptFileContent(RandomAccessFile file) throws Exception {
        CryptoHeaders cryptoHeaders = nxlHeaders.getCryptoHeaders();
        BasicHeaders basicHeaders = nxlHeaders.getBasicHeaders();
        int blockSize = DecryptionUtil.NXL_PAGE_SIZE;
        long bytesToRead = cryptoHeaders.getContentLength();
        if (bytesToRead == 0) {
            return null;
        }
        byte[] primaryKey = getCEK(cryptoHeaders);
        int rows = (int)Math.ceil((double)bytesToRead / Integer.MAX_VALUE);
        long startIndex = 0;//basicHeaders.getPointerOfContent();
        byte[][] decryptedFileArr = new byte[rows][];
        for (int i = 0; i < rows - 1; i++) {
            decryptedFileArr[i] = new byte[Integer.MAX_VALUE];
        }
        decryptedFileArr[rows - 1] = new byte[(int)(bytesToRead % Integer.MAX_VALUE)];
        int curRow = 0;
        int curCol = 0;
        int ivec = 0;
        try {
            while (bytesToRead >= blockSize) {
                curRow = (int)(startIndex / Integer.MAX_VALUE);
                curCol = (int)(startIndex % Integer.MAX_VALUE);
                byte[] encryptedChunk = DecryptionUtil.readBytes(file, startIndex + basicHeaders.getPointerOfContent(), DecryptionUtil.NXL_PAGE_SIZE);
                byte[] dePaddedFileArr = AESEncryptionUtil.processData(primaryKey,
                        encryptedChunk, blockSize, ivec, Cipher.DECRYPT_MODE);
                if ((curCol + 4096) / Integer.MAX_VALUE != curCol / Integer.MAX_VALUE) {
                    int spaceLeft = Integer.MAX_VALUE - curCol;
                    //					System.out.println("Space left is "+spaceLeft);
                    System.arraycopy(dePaddedFileArr, 0, decryptedFileArr[curRow],
                            curCol, spaceLeft);
                    System.arraycopy(dePaddedFileArr, spaceLeft, decryptedFileArr[curRow + 1],
                            0, dePaddedFileArr.length - spaceLeft);
                } else {
                    System.arraycopy(dePaddedFileArr, 0, decryptedFileArr[curRow],
                            curCol, dePaddedFileArr.length);
                }
                bytesToRead -= blockSize;
                startIndex += blockSize;
                ivec += blockSize;
            }
            if (bytesToRead > 0) {
                byte[] encryptedChunk = DecryptionUtil.readBytes(file, startIndex + basicHeaders.getPointerOfContent(), DecryptionUtil.NXL_PAGE_SIZE);
                byte[] dePaddedFileArr = AESEncryptionUtil.processData(primaryKey,
                        encryptedChunk, blockSize, ivec, Cipher.DECRYPT_MODE);
                curRow = (int)(startIndex / Integer.MAX_VALUE);
                curCol = (int)(startIndex % Integer.MAX_VALUE);
                if (((curCol + 4096) / Integer.MAX_VALUE) > 0) {
                    int spaceLeft = Integer.MAX_VALUE - curCol;
                    //					System.out.println("Space left is "+spaceLeft);
                    System.arraycopy(dePaddedFileArr, 0, decryptedFileArr[curRow],
                            curCol, spaceLeft);
                    System.arraycopy(dePaddedFileArr, spaceLeft, decryptedFileArr[curRow + 1],
                            0, dePaddedFileArr.length - spaceLeft);
                } else {
                    System.arraycopy(dePaddedFileArr, 0, decryptedFileArr[curRow], curCol, (int)bytesToRead);
                }
                bytesToRead = 0;
            }
        } catch (Exception e) {
            logger.error("Error occured while decrypting file content", e);
            //			System.out.println("CurRow: "+curRow);
            //			System.out.println("CurCol: "+curCol);
            //			System.out.println("Bytes to read: "+bytesToRead);
            //			System.out.println("StartIndex: "+startIndex);
            //			System.out.println("Changing point "+(curCol+4096)/Integer.MAX_VALUE);
        }
        return decryptedFileArr;
    }
}
