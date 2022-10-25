/**
 *
 */
package com.nextlabs.nxl.crypt;

import com.nextlabs.client.keyservice.KeyServiceSDKException;
import com.nextlabs.keymanagement.KeyRetrievalManager;
import com.nextlabs.kms.types.KeyDTO;
import com.nextlabs.nxl.exception.NXRTERROR;
import com.nextlabs.nxl.pojos.BasicHeaders;
import com.nextlabs.nxl.pojos.CryptoHeaders;
import com.nextlabs.nxl.pojos.NXLFileMetaData;
import com.nextlabs.nxl.pojos.NXLHeaders;
import com.nextlabs.nxl.pojos.NXLKeKeyID;
import com.nextlabs.nxl.pojos.NXLKeyBlob;
import com.nextlabs.nxl.pojos.NXLPadding;
import com.nextlabs.nxl.pojos.NXLSection;
import com.nextlabs.nxl.pojos.NextlabsKeyId;
import com.nextlabs.nxl.pojos.SectionTable;
import com.nextlabs.nxl.pojos.SignatureHeaders;
import com.nextlabs.nxl.util.DecryptionUtil;

import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.zip.CRC32;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author nnallagatla
 *
 */
public abstract class AbstractDecryptionHandler {

    protected NXLHeaders nxlHeaders = null;

    protected SectionTable sectionTable = null;

    protected NXLFileMetaData metaData = null;

    public long readTime;

    public long writeTime;

    private static Logger logger = LoggerFactory.getLogger("AbstractDecryptionHandler");

    protected NXLHeaders readHeaders(RandomAccessFile file, String tenantId) throws Exception {
        SignatureHeaders signatureHeaders = readSignatureHeaders(file);
        BasicHeaders basicHeaders = readBasicHeaders(file);
        CryptoHeaders cryptoHeaders = readCryptoHeaders(file, tenantId);
        nxlHeaders = new NXLHeaders();
        nxlHeaders.setBasicHeaders(basicHeaders);
        nxlHeaders.setCryptoHeaders(cryptoHeaders);
        nxlHeaders.setSignatureHeaders(signatureHeaders);
        return nxlHeaders;
    }

    protected CryptoHeaders readCryptoHeaders(RandomAccessFile file, String tenantId) throws Exception {
        CryptoHeaders cryptoHeaders = new CryptoHeaders();
        int algorithm = DecryptionUtil.readShort(file, 176, 4);
        //      System.out.println("Crypto Algorithm: "+algorithm);
        cryptoHeaders.setAlgorithm(algorithm);
        int cbcSize = DecryptionUtil.readInt(file, 180, 4);
        //      System.out.println("CBC Size: "+cbcSize);
        cryptoHeaders.setCbcSize(cbcSize);
        NXLKeyBlob primaryKeyBlob = readPrimaryKeyInfo(file, tenantId);
        validateChecksum(primaryKeyBlob.getCeKey(), file);
        cryptoHeaders.setPrimaryKey(primaryKeyBlob);
        NXLKeyBlob recoveryKeyBlob = readRecoveryKeyInfo(file);
        cryptoHeaders.setRecoveryKey(recoveryKeyBlob);
        long contentLength = DecryptionUtil.readLong(file, 824, 8);
        logger.debug("contentLength: " + contentLength);
        cryptoHeaders.setContentLength(contentLength);
        long allocateLength = DecryptionUtil.readLong(file, 832, 8);
        //      System.out.println("allocateLength: "+allocateLength);
        cryptoHeaders.setAllocateLength(allocateLength);
        NXLPadding nxlPadding = readPaddingData(file);
        cryptoHeaders.setNxlPadding(nxlPadding);
        return cryptoHeaders;
    }

    protected final byte[] getCEK(CryptoHeaders cryptoHeaders) {
        byte[] primaryKey = null;
        if (cryptoHeaders.getAlgorithm() == DecryptionUtil.NXL_ALGORITHM_AES256) {
            primaryKey = new byte[32];
            System.arraycopy(cryptoHeaders.getPrimaryKey().getCeKey(), 0, primaryKey, 0, 32);
        } else if (cryptoHeaders.getAlgorithm() == DecryptionUtil.NXL_ALGORITHM_AES128) {
            primaryKey = new byte[16];
            System.arraycopy(cryptoHeaders.getPrimaryKey().getCeKey(), 0, primaryKey, 0, 16);
        }
        return primaryKey;
    }

    protected final NXLSection readSections(int startIndex, RandomAccessFile file) throws Exception {
        NXLSection section = new NXLSection();
        String sectionName = DecryptionUtil.readUnsignedChar(file, startIndex, 8);
        logger.debug("Section Name: " + sectionName);
        section.setName(sectionName);
        startIndex += 8;
        int sectionSize = DecryptionUtil.readInt(file, startIndex, 4);
        logger.debug("section Size: " + sectionSize);
        section.setSize(sectionSize);
        startIndex += 4;
        int sectionCheckSum = DecryptionUtil.readInt(file, startIndex, 4);
        section.setChecksum(sectionCheckSum);
        //      System.out.println("section CheckSum: "+sectionCheckSum);
        return section;
    }

    public final NXLFileMetaData readMeta(RandomAccessFile file) throws Exception {
        metaData = new NXLFileMetaData(readSectionTable(file));
        return metaData;
    }

    protected final SectionTable readSectionTable(RandomAccessFile file) throws Exception {
        sectionTable = new SectionTable();
        byte[] checkSum = DecryptionUtil.readBytes(file, 872, 16);
        sectionTable.setChecksum(checkSum);
        int sectionCount = DecryptionUtil.readInt(file, 888, 4);
        if (sectionCount < 3) {
            throw new NXRTERROR("Default sections missing");
        }
        logger.debug("sectionCount: " + sectionCount);
        sectionTable.setCount(sectionCount);
        //Unused 4 bytes here
        NXLSection[] sections = new NXLSection[sectionCount];
        int startIndex = 2048;
        for (int i = 0; i < sectionCount; i++) {
            sections[i] = readSections(896 + 16 * i, file);
            sections[i].setSectionData(DecryptionUtil.readWCharSectionMap(file, startIndex, sections[i].getSize()));
            startIndex += sections[i].getSize();
        }
        sectionTable.setSections(sections);
        return sectionTable;
    }

    protected final NXLPadding readPaddingData(RandomAccessFile file) throws Exception {
        NXLPadding padding = new NXLPadding();
        int paddingSize = (int)Integer.parseInt(DecryptionUtil.readUnsignedChar(file, 840, 1));
        padding.setPaddingSize(paddingSize);
        //      System.out.println("Padding size: "+paddingSize);
        byte[] paddingData = DecryptionUtil.readBytes(file, 841, 31);
        padding.setPaddingData(paddingData);
        //      System.out.println("Padding data: "+paddingData);
        return padding;

    }

    protected final NXLKeyBlob readRecoveryKeyInfo(RandomAccessFile file) throws Exception {
        //Read Recovery Key info
        NXLKeyBlob recoveryKeyBlob = new NXLKeyBlob();
        NXLKeKeyID recoveryKeyId = readRecoveryEncryptionKey(file);
        recoveryKeyBlob.setKeyID(recoveryKeyId);
        byte[] recoveryKey = DecryptionUtil.readKey(file, 568, 256);
        recoveryKeyBlob.setCeKey(recoveryKey);
        //      System.out.println("Recovery Key: "+String.valueOf(recoveryKey));
        return recoveryKeyBlob;
    }

    protected final NXLKeKeyID readRecoveryEncryptionKey(RandomAccessFile file) throws Exception {
        NXLKeKeyID recoveryKeyId = new NXLKeKeyID();
        short algorithm = DecryptionUtil.readShort(file, 504, 2);
        recoveryKeyId.setAlgorithm(algorithm);
        //      System.out.println("Recovery Key Algorithm: "+algorithm);
        short idSize = DecryptionUtil.readShort(file, 506, 2);
        recoveryKeyId.setIdSize(idSize);
        //      System.out.println("idSize: "+idSize);
        byte[] id = DecryptionUtil.readKey(file, 508, 60);
        recoveryKeyId.setId(id);
        //      System.out.println("id: "+id);
        return recoveryKeyId;
    }

    protected static NXLKeyBlob readPrimaryKeyInfo(RandomAccessFile nxlFile, String tenantId) throws Exception {
        NXLKeyBlob cekBlob = new NXLKeyBlob();
        NXLKeKeyID nxlKeKeyID = readKeyEncryptionKey(nxlFile);
        cekBlob.setKeyID(nxlKeKeyID);
        byte[] pcKey = getKey(nxlFile, cekBlob.getKeyID().getNextlabsKeyId().getName(), cekBlob.getKeyID().getNextlabsKeyId().getHash(), cekBlob.getKeyID().getNextlabsKeyId().getTimestamp(), tenantId);
        byte[] aesKeyArr = DecryptionUtil.readKey(nxlFile, 248, 256);
        // Decrypt the contents
        byte[] decryptedAESKeyArr = AESEncryptionUtil.processData(pcKey, aesKeyArr, 256, 0, Cipher.DECRYPT_MODE);
        //byte[] decryptedAESKeyArr={(byte)0x56, (byte)0x38, (byte)0xbe, (byte)0x28, (byte)0xa6, (byte)0x52, (byte)0x45, (byte)0x84, (byte)0x1a, (byte)0x80, (byte)0x8e, (byte)0xf0, (byte)0x1d, (byte)0x97, (byte)0x69, (byte)0x6f, (byte)0xda, (byte)0x5, (byte)0xed, (byte)0x3a, (byte)0xc9, (byte)0x57, (byte)0x84, (byte)0x42, (byte)0xea, (byte)0x76, (byte)0x83, (byte)0xc3, (byte)0xbf, (byte)0xc, (byte)0x7d, (byte)0x65, };
        cekBlob.setCeKey(decryptedAESKeyArr);
        return cekBlob;
    }

    public static byte[] encryptDataWithCEK(RandomAccessFile encryptedFile, byte[] data, long ivec, String tenantId)
            throws Exception {
        NXLKeyBlob key = readPrimaryKeyInfo(encryptedFile, tenantId);
        byte[] keyToUse = new byte[16];
        System.arraycopy(key.getCeKey(), 0, keyToUse, 0, 16);
        return AESEncryptionUtil.processData(keyToUse, data, data.length, ivec, Cipher.ENCRYPT_MODE);
    }

    protected final void validateChecksum(byte[] decryptedAESKeyArr, RandomAccessFile file) throws Exception {
        //Calculate the checksum from the nxl file
        CRC32 crc = new CRC32();
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(sectionTable.getCount());
        crc.update(buffer.array(), 0, 4);
        //      System.out.println("The checksum value is after first calculation is: "+ value);
        byte[] sectionInfo = DecryptionUtil.readBytes(file, 896, sectionTable.getCount() * 16);
        crc.update(sectionInfo);
        long computedChecksum = crc.getValue();
        //      System.out.println("The checksum value after the first calculation is: "+ computedChecksum);
        //Decrypt the encrypted section table checksum from the nxl file metadata
        byte[] checksumKey = new byte[16];
        System.arraycopy(decryptedAESKeyArr, 0, checksumKey, 0, 16);
        byte[] decryptedChecksumBytes = AESEncryptionUtil.processData(checksumKey, sectionTable.getChecksum(), 16, 0, Cipher.DECRYPT_MODE);
        byte[] checksumValArray = new byte[8];
        System.arraycopy(decryptedChecksumBytes, 0, checksumValArray, 0, 4);
        ByteBuffer buffer1 = ByteBuffer.wrap(checksumValArray);
        buffer1.order(ByteOrder.LITTLE_ENDIAN);
        long decryptedChecksum = buffer1.getLong();
        //      System.out.println("decryptedChecksum:"+decryptedChecksum);
        //      System.out.println("computedChecksum:"+computedChecksum);
        if (decryptedChecksum != computedChecksum) {
            logger.error("Incorrect checksum. But let me continue and try to decrypt the file...");
            //          throw new NXRTERROR("Incorrect checksum. The file has been corrupted.");
        } else {
            logger.debug("The checksum is correct");
        }
    }

    protected static byte[] getKey(RandomAccessFile file, String keyRingName, byte[] keyId, long timeStamp,
        String tenantId) throws Exception {
        KeyDTO k = null;
        try {
            k = com.nextlabs.keymanagement.KeyRetrievalManager.getInstance().getKey(KeyRetrievalManager.keyStorePassword, keyRingName, keyId, timeStamp * 1000);
        } catch (KeyServiceSDKException e) {
            logger.error("Unable to get key:::", e);
            throw e;
        }
        return (k != null) ? k.getKeyValue() : null;
    }

    protected static NXLKeKeyID readKeyEncryptionKey(RandomAccessFile nxlFile) throws Exception {
        NXLKeKeyID keyEncryptionKey = new NXLKeKeyID();
        //Read Primary Key info
        short algorithm = DecryptionUtil.readShort(nxlFile, 184, 2);
        keyEncryptionKey.setAlgorithm(algorithm);
        //      System.out.println("Primary Key Algorithm: "+algorithm);
        short idSize = DecryptionUtil.readShort(nxlFile, 186, 2);
        keyEncryptionKey.setIdSize(idSize);
        //      System.out.println("idSize: "+idSize);
        NextlabsKeyId nextlabsKeyId = new NextlabsKeyId();
        String name = DecryptionUtil.readUnsignedChar(nxlFile, 188, 8);
        nextlabsKeyId.setName(name);
        //      System.out.println("name: "+name);
        //Read this as byte array
        byte[] hash = DecryptionUtil.readKey(nxlFile, 196, 32);
        nextlabsKeyId.setHash(hash);
        //      System.out.println("hash: "+DecryptionUtil.toHex(hash));
        int timeStamp = DecryptionUtil.readInt(nxlFile, 228, 4);
        nextlabsKeyId.setTimestamp(timeStamp);
        //      System.out.println("timeStamp: "+timeStamp);
        keyEncryptionKey.setNextlabsKeyId(nextlabsKeyId);
        return keyEncryptionKey;
    }

    protected final BasicHeaders readBasicHeaders(RandomAccessFile file) throws Exception {
        BasicHeaders basicHeaders = new BasicHeaders();
        String thumbPrint = DecryptionUtil.readUnsignedChar(file, 144, 16);
        basicHeaders.setThumbPrint(thumbPrint.toCharArray());
        logger.debug("thumbPrint: " + thumbPrint);
        short minVersion = DecryptionUtil.readShort(file, 160, 2);
        basicHeaders.setMinVersion(minVersion);
        logger.debug("minVersion: " + minVersion);
        short majVersion = DecryptionUtil.readShort(file, 162, 2);
        basicHeaders.setMajVersion(majVersion);
        logger.debug("majVersion: " + majVersion);
        int flags = DecryptionUtil.readInt(file, 164, 4);
        basicHeaders.setFlags(flags);
        logger.debug("flags: " + flags);
        int alignment = DecryptionUtil.readInt(file, 168, 4);
        basicHeaders.setAlignment(alignment);
        logger.debug("Alignment: " + alignment);
        int pointerOfContent = DecryptionUtil.readInt(file, 172, 4);
        basicHeaders.setPointerOfContent(pointerOfContent);
        logger.debug("Pointer of Content: " + pointerOfContent);
        return basicHeaders;
    }

    protected final SignatureHeaders readSignatureHeaders(RandomAccessFile file) throws Exception {
        SignatureHeaders signatureHeaders = new SignatureHeaders();
        String nxlSignatureCode = DecryptionUtil.readUnsignedChar(file, 0, 8);
        signatureHeaders.setNxlSignatureCode(nxlSignatureCode);
        //      System.out.println("nxlSignatureCode: "+nxlSignatureCode);
        String message = DecryptionUtil.readWCharStr(file, 8, 136);
        signatureHeaders.setMessage(message);
        //      System.out.println("Message: "+message);
        return signatureHeaders;
    }

    protected final void validateHeaderInfo() throws NXRTERROR {
        //*****************************************
        //  Quick Check
        //*****************************************

        // check signature
        if (!DecryptionUtil.NXL_SIGNATURE.equals(nxlHeaders.getSignatureHeaders().getNxlSignatureCode())) {
            throw new NXRTERROR("NXL signature code not valid");
        }

        //*****************************************
        //  Full Check
        //*****************************************

        // check version
        if (DecryptionUtil.NXL_MAJOR_VERSION_10 != nxlHeaders.getBasicHeaders().getMajVersion()) {
            throw new NXRTERROR("Invalid major version");
        }

        // check alignment
        if (DecryptionUtil.NXL_PAGE_SIZE != nxlHeaders.getBasicHeaders().getAlignment()) {
            throw new NXRTERROR("Invalid alignment value");
        }

        // check data offset
        if (nxlHeaders.getBasicHeaders().getPointerOfContent() < DecryptionUtil.NXL_MIN_SIZE || 0 != (nxlHeaders.getBasicHeaders().getPointerOfContent() % DecryptionUtil.NXL_PAGE_SIZE)) {
            throw new NXRTERROR("Invalid Pointer of Content");
        }

        // Check Thumbprint
        char[] zerothumb = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        if (Arrays.equals(zerothumb, nxlHeaders.getBasicHeaders().getThumbPrint())) {
            throw new NXRTERROR("Invalid thumbprint");
        }

        // Check Algorithm
        if (DecryptionUtil.NXL_ALGORITHM_AES256 != nxlHeaders.getCryptoHeaders().getAlgorithm() && DecryptionUtil.NXL_ALGORITHM_AES128 != nxlHeaders.getCryptoHeaders().getAlgorithm()) {
            throw new NXRTERROR("Unsupported encryption algorithm for CEK");
        }

        // check cbc size
        if (nxlHeaders.getCryptoHeaders().getCbcSize() != DecryptionUtil.NXL_CBC_SIZE) {
            throw new NXRTERROR("Invalid CBC size");
        }

        // Check KEKs

        // a. Primary KEK
        if (nxlHeaders.getCryptoHeaders().getPrimaryKey().getKeyID().getAlgorithm() != DecryptionUtil.NXL_ALGORITHM_AES256) {
            throw new NXRTERROR("Unsupported encryption algorithm for KEK");
        }

        // Check section count
        if (sectionTable.getSections().length < 3) {
            throw new NXRTERROR("Section count is less than 3");
        }

        // Check section ".Attrs"
        if (!sectionTable.getSections()[0].getName().equals(DecryptionUtil.NXL_SECTION_ATTRIBUTES)) {
            throw new NXRTERROR("Default section doesn't exist");
        }
        if (0 == sectionTable.getSections()[0].getSize() || (2048 != sectionTable.getSections()[0].getSize() && 0 != (sectionTable.getSections()[0].getSize() % DecryptionUtil.NXL_PAGE_SIZE))) {
            throw new NXRTERROR("Invalid section size");
        }

        // Check section ".Rights"
        if (!sectionTable.getSections()[1].getName().equals(DecryptionUtil.NXL_SECTION_RIGHTS)) {
            throw new NXRTERROR("Default section doesn't exist");
        }
        if (0 == sectionTable.getSections()[1].getSize() || (2048 != sectionTable.getSections()[1].getSize() && 0 != (sectionTable.getSections()[1].getSize() % DecryptionUtil.NXL_PAGE_SIZE))) {
            throw new NXRTERROR("Invalid section size");
        }

        // Check section ".Tags"
        if (!sectionTable.getSections()[2].getName().equals(DecryptionUtil.NXL_SECTION_TAGS)) {
            throw new NXRTERROR("Default section doesn't exist");
        }
        if (0 == sectionTable.getSections()[2].getSize() || (2048 != sectionTable.getSections()[2].getSize() && 0 != (sectionTable.getSections()[2].getSize() % DecryptionUtil.NXL_PAGE_SIZE))) {
            throw new NXRTERROR("Invalid section size");
        }
    }

}
