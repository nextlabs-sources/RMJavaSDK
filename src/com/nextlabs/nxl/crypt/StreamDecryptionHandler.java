package com.nextlabs.nxl.crypt;

import com.nextlabs.nxl.Constants;

/**
 * @author nnallagatla
 *
 */

import com.nextlabs.nxl.pojos.CryptoHeaders;
import com.nextlabs.nxl.pojos.NXLFileMetaData;
import com.nextlabs.nxl.util.DecryptionUtil;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.List;
import java.util.UUID;

import javax.crypto.Cipher;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class StreamDecryptionHandler extends AbstractDecryptionHandler {

    private static Logger logger = LoggerFactory.getLogger("StreamDecryptionHandler");
    byte[] headerContent;

    public StreamDecryptionHandler(byte[] header, String tenantId) throws Exception {
        this.headerContent = header;
        ByteArrayInputStream stream = new ByteArrayInputStream(header);
        parseStreamContent(stream, tenantId);
    }

    public StreamDecryptionHandler(byte[] header) throws Exception {
        this(header, null);
    }

    public StreamDecryptionHandler(StreamDecryptionState state) throws Exception {
        this(state.getHeaderContent(), null);
    }

    private void parseStreamContent(InputStream in, String tenantId) throws Exception {
        RandomAccessFile nxlFile = null;
        File tempFile = new File(System.getProperty("java.io.tmpdir"), UUID.randomUUID() + ".NXL");

        BufferedInputStream bis = null;
        BufferedOutputStream bos = null;

        try {
            bis = new BufferedInputStream(in);
            bos = new BufferedOutputStream(new FileOutputStream(tempFile));
            IOUtils.copy(bis, bos);
        } finally {
            if (bis != null) {
                bis.close();
            }
            if (bos != null) {
                bos.close();
            }
        }

        try {
            nxlFile = new RandomAccessFile(tempFile, "r");
            readMeta(nxlFile);
            if (nxlHeaders == null) {
                readHeaders(nxlFile, tenantId);
                validateHeaderInfo();
            }
        } finally {
            if (nxlFile != null) {
                nxlFile.close();
            }
            try {
                tempFile.delete();
            } catch (Exception e) {
                logger.debug("Unable to delete temp file at " + tempFile.getAbsolutePath(), e);
            }
        }
    }
    
    public long getOriginalContentLength(){
        return nxlHeaders.getCryptoHeaders().getContentLength();
    }

    /**
     *
     * @param encryptedStream
     * @param outputStream
     * @throws Exception
     */
    public void decryptAndWriteFileContent(InputStream encryptedStream, OutputStream outputStream) throws Exception {
        decryptAndWriteFileContent(encryptedStream, outputStream, null);
    }

    public void decryptPartial(InputStream encryptedStream, OutputStream outputStream, long start, long length, boolean skip)
            throws Exception {
        if (start < 0 || start>= nxlHeaders.getCryptoHeaders().getContentLength() ||length > nxlHeaders.getCryptoHeaders().getContentLength() || length <= 0) {
            throw new IllegalArgumentException("Invalid range");
        }
        
        int blockSize = DecryptionUtil.NXL_PAGE_SIZE;
        long bytesToReadStart = (long)blockSize * (start / blockSize);
        
        int startOffset = (int)(start - bytesToReadStart);
        long bytesToRead = length + startOffset;

        byte[] primaryKey = getCEK(nxlHeaders.getCryptoHeaders());
        long ivec = bytesToReadStart;
        
        if(skip) {
            encryptedStream.read(new byte[(int)bytesToReadStart]);
        }
        boolean firstBlock = true;
        //System.out.println("Total bytes to read: " + bytesToRead);
        try {
            while (bytesToRead >= blockSize) {
                long startRead = System.currentTimeMillis();
                byte[] encryptedChunk = new byte[blockSize];
                encryptedStream.read(encryptedChunk);
                readTime += System.currentTimeMillis() - startRead;
                byte[] decryptedChunk = AESEncryptionUtil.processData(primaryKey, encryptedChunk, blockSize, ivec, Cipher.DECRYPT_MODE);
                long startWrite = System.currentTimeMillis();              
                if(firstBlock) {
                    int len = blockSize - startOffset;
                    byte[] decryptedChunkOffset = new byte[(int)len];
                    System.arraycopy(decryptedChunk, startOffset, decryptedChunkOffset, 0, len);
                    //System.out.println("Copying from " + startOffset + " to " + (start+len-1));
                    outputStream.write(decryptedChunkOffset);
                    firstBlock = false;
                } else {
                    //System.out.println("Copying whole block");
                    outputStream.write(decryptedChunk);
                }
                writeTime += System.currentTimeMillis() - startWrite;
                bytesToRead -= blockSize;
                ivec += blockSize;
            }

            if(bytesToRead > 0) {
                //System.out.println("Remaining bytes to read: " + bytesToRead);
                byte[] encryptedChunk = new byte[blockSize];
                encryptedStream.read(encryptedChunk);
                byte[] decryptedChunk = AESEncryptionUtil.processData(primaryKey, encryptedChunk, blockSize, ivec,Cipher.DECRYPT_MODE);
                if (firstBlock) {
                    byte[] decryptedChunkOffset = new byte[(int)length];
                    System.arraycopy(decryptedChunk, startOffset, decryptedChunkOffset, 0, (int)length);
                    //System.out.println("Copying first block from " + startOffset + " to " + (start+length-1));
                    outputStream.write(decryptedChunkOffset);
                } else {
                    int len = (int) bytesToRead;
                    byte[] decryptedChunkOffset = new byte[len];
                    System.arraycopy(decryptedChunk, 0, decryptedChunkOffset, 0, len);
                    //System.out.println("Copying last " +  len + " bytes");
                    outputStream.write(decryptedChunkOffset);
                }
            }
            
        } catch (IOException e) {
            logger.error("Error occured while writing file", e);
        } finally {
            try {
                outputStream.close();
            } catch (IOException e) {
                logger.error("Error occured while writing file" + e);
            }
        }
    }

    public void decryptAndWriteFileContent(InputStream encryptedStream, OutputStream outputStream, String tenantId)
            throws Exception {

        if (nxlHeaders == null) {
            throw new IllegalStateException("StreamDecryptionHandler not initialized properly");
        }

        CryptoHeaders cryptoHeaders = nxlHeaders.getCryptoHeaders();
        int blockSize = DecryptionUtil.NXL_PAGE_SIZE;
        long bytesToRead = cryptoHeaders.getContentLength();
        System.out.println("Bytes to Read: " + bytesToRead);
        byte[] primaryKey = getCEK(cryptoHeaders);
        long ivec = 0;
        try {
            while (bytesToRead >= blockSize) {
                long startRead = System.currentTimeMillis();
                byte[] encryptedChunk = new byte[blockSize];
                encryptedStream.read(encryptedChunk);
                readTime += System.currentTimeMillis() - startRead;
                byte[] decryptedChunk = AESEncryptionUtil.processData(primaryKey, encryptedChunk, blockSize, ivec, Cipher.DECRYPT_MODE);
                long startWrite = System.currentTimeMillis();
                outputStream.write(decryptedChunk);
                writeTime += System.currentTimeMillis() - startWrite;
                bytesToRead -= blockSize;
                ivec += blockSize;
            }
            if (bytesToRead > 0) {
                byte[] encryptedChunk = new byte[blockSize];
                encryptedStream.read(encryptedChunk);
                byte[] decryptedChunk = AESEncryptionUtil.processData(primaryKey, encryptedChunk, blockSize, ivec, Cipher.DECRYPT_MODE);
                byte[] unpaddedArray = new byte[(int)bytesToRead];
                System.arraycopy(decryptedChunk, 0, unpaddedArray, 0, (int)bytesToRead);
                outputStream.write(unpaddedArray);
                bytesToRead = 0;
            }
        } catch (IOException e) {
            logger.error("Error occured while writing file", e);
        } finally {
            try {
                outputStream.close();
            } catch (IOException e) {
                logger.error("Error occured while writing file" + e);
            }
        }
    }

    public NXLFileMetaData getNXLFileMetadata() {
        return metaData;
    }

    public StreamDecryptionState getState() {
        long contentLength = nxlHeaders.getCryptoHeaders().getContentLength();
        String extension = null;
        List<String> values = getNXLFileMetadata().getAttr().get(Constants.ATTR_FILE_EXTENSION);
        if (values != null && values.size() > 0) {
            extension = values.get(0);
        }
        StreamDecryptionState state = new StreamDecryptionState(contentLength, extension, getNXLFileMetadata(), headerContent);
        return state;
    }
}
