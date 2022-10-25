package com.nextlabs.nxl.crypt;

import com.nextlabs.client.keyservice.KeyServiceSDKException;
import com.nextlabs.keymanagement.KeyRetrievalManager;
import com.nextlabs.kms.types.KeyDTO;
import com.nextlabs.nxl.Constants;
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
import com.nextlabs.nxl.util.EncryptionUtil;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;
import java.util.zip.CRC32;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class EncryptionHandler {

    public static final int TAGS_LENGTH = 4096;
    public static final int RIGHTS_LENGTH = 4096;
    public static final int ATTRIBUTES_LENGTH = 2048;
    public static final String KEYRINGNAME_NL_SHARE = "NL_SHARE";
    private byte[] pcKey;
    private byte[] ceKey;
    private NXLHeaders nxlHeaders;
    private SectionTable sectionTable;
    private NXLFileMetaData metadata;

    private ArrayList<NXLSection> sectionList;
    private static Logger logger = LoggerFactory.getLogger("EncryptionHandler");

    public EncryptionHandler() {
        sectionList = new ArrayList<NXLSection>();
        sectionTable = new SectionTable();
        metadata = new NXLFileMetaData(sectionTable);
    }

    public NXLFileMetaData encrypt(RandomAccessFile originalFile, RandomAccessFile nxlFile, String fileName,
        Map<String, List<String>> fileAttr, Map<String, List<String>> fileRights, Map<String, List<String>> fileTags,
        String tenantId) throws Exception {
        if (fileAttr == null) {
            fileAttr = new HashMap<String, List<String>>();
        }
        if (fileRights == null) {
            fileRights = new HashMap<String, List<String>>();
        }
        if (fileTags == null) {
            fileTags = new HashMap<String, List<String>>();
        }
        createHeaders(nxlFile, originalFile.length(), tenantId);
        writeSectionTable(nxlFile, fileName, fileAttr, fileRights, fileTags);
        encryptContent(originalFile, nxlFile);
        return metadata;
    }

    public NXLFileMetaData encryptStream(InputStream in, OutputStream out, long contentLength, String fileName,
        Map<String, List<String>> fileAttr, Map<String, List<String>> fileRights, Map<String, List<String>> fileTags,
        String tenantId) throws Exception {
        if (fileAttr == null) {
            fileAttr = new HashMap<String, List<String>>();
        }
        if (fileRights == null) {
            fileRights = new HashMap<String, List<String>>();
        }
        if (fileTags == null) {
            fileTags = new HashMap<String, List<String>>();
        }

        RandomAccessFile nxlRAF = null;
        File tempFile = new File(System.getProperty("java.io.tmpdir"), UUID.randomUUID() + ".NXL");
        try {
            nxlRAF = new RandomAccessFile(tempFile, "rw");
            createHeaders(nxlRAF, contentLength, tenantId);
            writeSectionTable(nxlRAF, fileName, fileAttr, fileRights, fileTags);
            EncryptionUtil.writeBytes(nxlRAF, new byte[] { 0 }, ((long)nxlHeaders.getBasicHeaders().getPointerOfContent() - 1));
            writeMetadataToStream(nxlRAF, out);
            encryptContent(in, out);
            return metadata;
        } finally {
            if (nxlRAF != null) {
                nxlRAF.close();
            }
            try {
                tempFile.delete();
            } catch (Exception e) {
                logger.debug("Unable to delete temp file at " + tempFile.getAbsolutePath(), e);
            }
        }
    }

    private void writeMetadataToStream(RandomAccessFile nxlRAF, OutputStream out) throws Exception {
        int blockSize = 512;
        nxlRAF.seek(0);
        byte[] chunk = new byte[blockSize];
        int numRead = 0;
        while ((numRead = nxlRAF.read(chunk)) >= 0) {
            EncryptionUtil.writeBytes(out, chunk, 0, numRead);
        }
    }

    private void modifySectionTable(RandomAccessFile nxlFile, String tenantId) throws Exception {
        //Calculates the checksum and writes it to the nxl file.
        long checksum = calculateSectionTableChecksum(nxlFile);
        byte[] encryptedCheckSum = updateCheckSumForEncryptedFile(nxlFile, checksum, tenantId);
        writeSectionTableMetaData(nxlFile, encryptedCheckSum);
    }

    private byte[] updateCheckSumForEncryptedFile(RandomAccessFile nxlFile, long checksum, String tenantId)
            throws Exception {
        ByteBuffer buffer1 = ByteBuffer.allocate(8);
        buffer1.order(ByteOrder.LITTLE_ENDIAN);
        buffer1.putInt((int)checksum);
        byte[] checksumArray = new byte[16];
        System.arraycopy(buffer1.array(), 0, checksumArray, 0, 4);
        byte[] encrytpedChecksum = DecryptionHandler.encryptDataWithCEK(nxlFile, checksumArray, 0, tenantId);
        return encrytpedChecksum;
    }

    private void writeSectionTable(RandomAccessFile nxlFile, String fileName, Map<String, List<String>> fileAttr,
        Map<String, List<String>> fileRights, Map<String, List<String>> fileTags) throws Exception {
        //Creates sections pojo and adds it to sectionData list.
        addDefaultSections(fileName, fileAttr, fileRights, fileTags);
        //Writes all the sections metadata and data to the nxl file.
        writeSections(nxlFile);
        long checksum = calculateSectionTableChecksum(nxlFile);
        byte[] encryptedChecksum = encryptCheckSum(checksum);
        //Calculates the checksum and writes it to the nxl file.
        writeSectionTableMetaData(nxlFile, encryptedChecksum);
    }

    private byte[] encryptCheckSum(long checksum) {
        byte[] key = new byte[16];
        System.arraycopy(ceKey, 0, key, 0, 16);
        ByteBuffer buffer1 = ByteBuffer.allocate(8);
        buffer1.order(ByteOrder.LITTLE_ENDIAN);
        buffer1.putInt((int)checksum);
        byte[] checksumArray = new byte[16];
        System.arraycopy(buffer1.array(), 0, checksumArray, 0, 4);
        byte[] encrytpedChecksum = AESEncryptionUtil.processData(key, checksumArray, 16, 0, Cipher.ENCRYPT_MODE);
        return encrytpedChecksum;
    }

    private void writeSectionTableMetaData(RandomAccessFile nxlFile, byte[] encryptedChecksum) throws Exception {
        //		System.out.println("Encrypted Checksum is: "+DecryptionUtil.toHex(encryptedChecksum));
        sectionTable.setChecksum(encryptedChecksum);
        EncryptionUtil.writeBytes(nxlFile, encryptedChecksum, 872);
        EncryptionUtil.writeInt(nxlFile, sectionTable.getCount(), 888);
    }

    private long calculateSectionTableChecksum(RandomAccessFile nxlFile) throws Exception {
        CRC32 crc = new CRC32();
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(sectionTable.getCount());
        crc.update(buffer.array(), 0, 4);
        byte[] sectionInfo = DecryptionUtil.readBytes(nxlFile, 896, sectionTable.getCount() * 16);
        crc.update(sectionInfo);
        long checksum = crc.getValue();
        return checksum;
    }

    private void writeSections(RandomAccessFile nxlFile) throws Exception {
        sectionTable.setCount(sectionList.size());
        NXLSection[] sections = new NXLSection[sectionList.size()];
        sections = sectionList.toArray(sections);
        sectionTable.setSections(sections);
        int startInfoIndex = 896;
        int startDataIndex = 2048;
        //Iterate over all the sections set in the sectionTable and write them to the nxl file.
        for (int i = 0; i < sectionTable.getCount(); i++) {
            writeSection(nxlFile, startInfoIndex, startDataIndex, sections[i]);
            startDataIndex += sections[i].getSize();
            startInfoIndex += 16;
        }
    }

    private void writeSection(RandomAccessFile nxlFile, int startInfoIndex, int startDataIndex, NXLSection section)
            throws Exception {
        EncryptionUtil.writeString(nxlFile, section.getName(),
                startInfoIndex);
        EncryptionUtil.writeInt(nxlFile, section.getSize(),
                startInfoIndex + 8);
        String sectionDataString = getSectionDataString(section.getSectionData());

        EncryptionUtil.writeWCharArr(nxlFile, sectionDataString.toString(),
                startDataIndex);
        byte[] sectionData = DecryptionUtil.readBytes(nxlFile, startDataIndex, sectionDataString.length() * 2);
        byte[] sectionDataArray = new byte[section.getSize()];
        System.arraycopy(sectionData, 0, sectionDataArray, 0, sectionData.length);
        CRC32 crc = new CRC32();
        crc.update(sectionDataArray);
        section.setChecksum((int)crc.getValue());
        EncryptionUtil.writeInt(nxlFile, section.getChecksum(),
                startInfoIndex + 12);
    }

    public static String getSectionDataString(Map<String, List<String>> map) {
        Iterator<Entry<String, List<String>>> it = map.entrySet().iterator();
        StringBuilder buffer = new StringBuilder();
        // Iterate over the map and create a list of strings to be written to the file.
        while (it.hasNext()) {
            Entry<String, List<String>> entry = (Entry<String, List<String>>)it.next();
            if (entry.getValue() != null) {
                Iterator<String> valueIterator = entry.getValue().iterator();
                while (valueIterator.hasNext()) {
                    String value = valueIterator.next();
                    if (value != null) {
                        buffer.append(entry.getKey() + "=" + value);
                    } else {
                        buffer.append(entry.getKey() + "=" + "");
                    }
                    buffer.append("\0");
                }
            } else {
                buffer.append(entry.getKey() + "=" + "");
                buffer.append("\0");
            }
        }
        buffer.append("\0");
        return buffer.toString();
    }

    public void modifySection(RandomAccessFile nxlFile, int sectionNumber, SectionTable secTable, String tenantId)
            throws Exception {
        sectionTable = secTable;
        NXLSection[] sections = sectionTable.getSections();
        int startDataIndex = 2048;
        int startInfoIndex = 896;
        for (int i = 0; i < sectionNumber; i++) {
            startInfoIndex += 16;
            startDataIndex += sections[i].getSize();
        }
        NXLSection section = sections[sectionNumber];
        //Rewrite Section bytes to 0.
        EncryptionUtil.writeBytes(nxlFile, new byte[section.getSize()], startDataIndex);
        writeSection(nxlFile, startInfoIndex, startDataIndex, section);
        modifySectionTable(nxlFile, tenantId);
    }

    private void addDefaultSections(String fileName, Map<String, List<String>> attributes,
        Map<String, List<String>> rights, Map<String, List<String>> tags) throws NXRTERROR {
        if (sectionList.size() > 0) {
            return;
        }
        // The filename is added as an attribute by the C++ API
        if (!attributes.containsKey(Constants.ATTR_FILE_EXTENSION)) {
            String ext = "";
            if (fileName.indexOf(".") != -1) {
                ext = fileName.substring(fileName.lastIndexOf("."));
            }
            List<String> fileExt = new ArrayList<String>();
            fileExt.add(ext);
            attributes.put(Constants.ATTR_FILE_EXTENSION, fileExt);
        }
        // Don't change this order.
        addSection(DecryptionUtil.NXL_SECTION_ATTRIBUTES, ATTRIBUTES_LENGTH, attributes, 0);
        addSection(DecryptionUtil.NXL_SECTION_RIGHTS, RIGHTS_LENGTH, rights, 1);
        addSection(DecryptionUtil.NXL_SECTION_TAGS, TAGS_LENGTH, tags, 2);
    }

    private void addSection(String name, int size, Map<String, List<String>> map,
        int position) throws NXRTERROR {
        NXLSection section = createSection(name, size, map);
        sectionList.add(position, section);
    }

    public void addSection(String name, int size, Map<String, List<String>> map)
            throws NXRTERROR {
        if (sectionList.size() >= 72) {
            throw new NXRTERROR("Maximum section count(72) exceeded.");
        }
        NXLSection section = createSection(name, size, map);
        sectionList.add(section);
    }

    private NXLSection createSection(String name, int size,
        Map<String, List<String>> map) throws NXRTERROR {
        if (name.length() > 8) {
            throw new NXRTERROR(
                    "The section name's length must be less than or equal to 8 characters");
        }
        if (map == null) {
            throw new NXRTERROR(
                    "Section data is null. Pass an empty hashmap for empty section.");
        }
        NXLSection section = new NXLSection();
        section.setName(name);
        section.setSize(size);
        section.setSectionData(map);
        section.setChecksum(0);
        return section;
    }

    private void encryptContent(RandomAccessFile originalFile, RandomAccessFile nxlFile) throws Exception {
        CryptoHeaders cryptoHeaders = nxlHeaders.getCryptoHeaders();
        BasicHeaders basicHeaders = nxlHeaders.getBasicHeaders();
        long iterationCount = 0;
        int blockSize = DecryptionUtil.NXL_PAGE_SIZE;
        long paddedContentLength = DecryptionUtil.roundToSize(
                cryptoHeaders.getContentLength(), blockSize);
        long bytesToRead = paddedContentLength;
        long ivec = 0;
        while (bytesToRead >= blockSize) {
            byte[] dataChunk = DecryptionUtil.readBytes(originalFile,
                    iterationCount * blockSize, blockSize);
            byte[] encryptedChunk = AESEncryptionUtil.processData(ceKey, dataChunk,
                    blockSize, ivec, Cipher.ENCRYPT_MODE);
            EncryptionUtil.writeBytes(nxlFile, encryptedChunk,
                    basicHeaders.getPointerOfContent() + iterationCount
                            * blockSize);
            bytesToRead -= blockSize;
            ivec += blockSize;
            iterationCount++;
        }
    }

    private void encryptContent(InputStream in, OutputStream out) throws Exception {
        CryptoHeaders cryptoHeaders = nxlHeaders.getCryptoHeaders();
        int blockSize = DecryptionUtil.NXL_PAGE_SIZE;
        long paddedContentLength = DecryptionUtil.roundToSize(
                cryptoHeaders.getContentLength(), blockSize);
        long bytesToRead = paddedContentLength;
        long ivec = 0;
        while (bytesToRead >= blockSize) {
            byte[] dataChunk = new byte[blockSize];
            in.read(dataChunk);
            byte[] encryptedChunk = AESEncryptionUtil.processData(ceKey, dataChunk,
                    blockSize, ivec, Cipher.ENCRYPT_MODE);
            EncryptionUtil.writeBytes(out, encryptedChunk);
            bytesToRead -= blockSize;
            ivec += blockSize;
        }
    }

    // Writing the headers and other meta data
    private void createHeaders(RandomAccessFile nxlFile, long originalFileSizeInBytes, String tenantId)
            throws Exception {
        SignatureHeaders signatureHeaders = writeSignatureHeaders(nxlFile);
        BasicHeaders basicHeaders = writeBasicHeaders(nxlFile);
        CryptoHeaders cryptoHeaders = writeCryptoHeaders(nxlFile, originalFileSizeInBytes, tenantId);
        nxlHeaders = new NXLHeaders();
        nxlHeaders.setSignatureHeaders(signatureHeaders);
        nxlHeaders.setBasicHeaders(basicHeaders);
        nxlHeaders.setCryptoHeaders(cryptoHeaders);
    }

    private SignatureHeaders writeSignatureHeaders(RandomAccessFile nxlFile) throws Exception {
        SignatureHeaders signatureHeaders = new SignatureHeaders();
        String signature = DecryptionUtil.NXL_SIGNATURE + "\0";
        signatureHeaders.setNxlSignatureCode(signature);
        EncryptionUtil.writeString(nxlFile, signature, 0);
        signatureHeaders.setMessage(DecryptionUtil.NXL_DEFAULT_MSG);
        EncryptionUtil
                .writeWCharArr(nxlFile, DecryptionUtil.NXL_DEFAULT_MSG, 8);
        return signatureHeaders;
    }

    private BasicHeaders writeBasicHeaders(RandomAccessFile nxlFile) throws Exception {
        BasicHeaders basicHeaders = new BasicHeaders();
        byte[] thumbPrint = createThumbPrint();
        basicHeaders.setThumbPrint(new String(thumbPrint).toCharArray());
        EncryptionUtil.writeBytes(nxlFile, thumbPrint, 144);
        short minVersion = DecryptionUtil.NXL_MINOR_VERSION_10;
        basicHeaders.setMinVersion(minVersion);
        EncryptionUtil.writeShort(nxlFile, minVersion, 160);
        short majVersion = DecryptionUtil.NXL_MAJOR_VERSION_10;
        basicHeaders.setMajVersion(majVersion);
        EncryptionUtil.writeShort(nxlFile, majVersion, 162);
        int flag = DecryptionUtil.NXL_FLAGS_NONE;
        basicHeaders.setFlags(flag);
        EncryptionUtil.writeInt(nxlFile, flag, 164);
        int alignment = DecryptionUtil.NXL_PAGE_SIZE;
        basicHeaders.setAlignment(alignment);
        EncryptionUtil.writeInt(nxlFile, alignment, 168);
        int pointerOfContent = DecryptionUtil.NXL_MIN_SIZE;
        basicHeaders.setPointerOfContent(pointerOfContent);
        EncryptionUtil.writeInt(nxlFile, pointerOfContent, 172);
        return basicHeaders;
    }

    private CryptoHeaders writeCryptoHeaders(RandomAccessFile nxlFile, long originalFileSizeInBytes, String tenantId)
            throws Exception {
        CryptoHeaders cryptoHeaders = new CryptoHeaders();
        int algorithm = DecryptionUtil.NXL_ALGORITHM_AES256;
        cryptoHeaders.setAlgorithm(algorithm);
        EncryptionUtil.writeInt(nxlFile, algorithm, 176);
        int cbcSize = DecryptionUtil.NXL_CBC_SIZE;
        cryptoHeaders.setCbcSize(cbcSize);
        EncryptionUtil.writeInt(nxlFile, cbcSize, 180);
        NXLKeyBlob primaryKeyBlob = writePrimaryKeyInfo(nxlFile, tenantId);
        cryptoHeaders.setPrimaryKey(primaryKeyBlob);
        // Recovery Key not implemented
        long contentLength = originalFileSizeInBytes;
        cryptoHeaders.setContentLength(contentLength);
        EncryptionUtil.writeLong(nxlFile, contentLength, 824);
        long allocateLength = 0;
        cryptoHeaders.setAllocateLength(allocateLength);
        EncryptionUtil.writeLong(nxlFile, allocateLength, 832);
        NXLPadding nxlPadding = createNxlPadding(nxlFile);
        cryptoHeaders.setNxlPadding(nxlPadding);
        return cryptoHeaders;
    }

    private NXLPadding createNxlPadding(RandomAccessFile nxlFile) throws Exception {
        NXLPadding nxlPadding = new NXLPadding();
        char size = 0;
        nxlPadding.setPaddingSize((int)size);
        EncryptionUtil.writeString(nxlFile, "" + size, 840);
        byte[] paddingData = new byte[31];
        nxlPadding.setPaddingData(paddingData);
        EncryptionUtil.writeBytes(nxlFile, paddingData, 841);
        return nxlPadding;
    }

    private NXLKeyBlob writePrimaryKeyInfo(RandomAccessFile nxlFile, String tenantId) throws Exception {
        NXLKeyBlob cekBlob = new NXLKeyBlob();
        NXLKeKeyID nxlKeKeyID = writeKeyEncryptionKey(nxlFile, tenantId);
        cekBlob.setKeyID(nxlKeKeyID);
        ceKey = generateCEKey();
        byte[] ceKeyPadded = new byte[256];
        System.arraycopy(ceKey, 0, ceKeyPadded, 0, 32);
        byte[] encryptedCEKey = AESEncryptionUtil.processData(pcKey, ceKeyPadded,
                ceKeyPadded.length, 0, Cipher.ENCRYPT_MODE);
        EncryptionUtil.writeBytes(nxlFile, encryptedCEKey, 248);
        cekBlob.setCeKey(encryptedCEKey);
        return cekBlob;
    }

    public byte[] createThumbPrint() {
        UUID uid = UUID.randomUUID();
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(uid.getMostSignificantBits());
        bb.putLong(uid.getLeastSignificantBits());
        return bb.array();
    }

    // Generate a 32 byte random Content Encryption Key that will be used to
    // encrypt content
    private byte[] generateCEKey() {
        byte[] randomKey = new byte[32];
        AESEncryptionUtil.generateNewKey(randomKey);
        return randomKey;
    }

    private NXLKeKeyID writeKeyEncryptionKey(RandomAccessFile nxlFile, String tenantId) throws Exception {
        NXLKeKeyID keyEncryptionKey = new NXLKeKeyID();
        short algorithm = DecryptionUtil.NXL_ALGORITHM_AES256;
        keyEncryptionKey.setAlgorithm(algorithm);
        EncryptionUtil.writeShort(nxlFile, algorithm, 184);
        //Should this be configurable. It is hardcoded in the C++ API
        String keyRingName = KEYRINGNAME_NL_SHARE;
        KeyDTO pcKeyStructure = getLatestKey(nxlFile, keyRingName, tenantId);
        // This is the decrypted Shared key which is used to encrypt to Content Encryption Key
        pcKey = pcKeyStructure.getKeyValue();
        short idSize = (short)(pcKey.length + keyRingName.length() + 4);
        //		System.out.println("Id Size is: " + idSize);
        keyEncryptionKey.setIdSize(idSize);
        EncryptionUtil.writeShort(nxlFile, idSize, 186);
        byte[] hash = pcKeyStructure.getKeyId().getHash();
        long timestamp = pcKeyStructure.getKeyId().getTimestamp();
        byte[] id = getKeyId(idSize, keyRingName, hash, timestamp);
        keyEncryptionKey.setId(id);
        EncryptionUtil.writeBytes(nxlFile, id, 188);
        NextlabsKeyId keyId = createNextlabsKeyId(hash, timestamp, keyRingName);
        keyEncryptionKey.setNextlabsKeyId(keyId);
        return keyEncryptionKey;
    }

    private byte[] getKeyId(short idSize, String keyRingName,
        byte[] keyId, long timestamp) {
        byte[] id = new byte[idSize];
        byte[] keyRingNameBytes = keyRingName.getBytes();
        int timeStamp = (int)(timestamp / 1000);
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(timeStamp);
        byte[] timeStampBytes = buffer.array();
        System.arraycopy(keyRingNameBytes, 0, id, 0, keyRingNameBytes.length);
        System.arraycopy(keyId, 0, id, keyRingNameBytes.length, keyId.length);
        System.arraycopy(timeStampBytes, 0, id, idSize - 4, 4);
        return id;
    }

    private NextlabsKeyId createNextlabsKeyId(byte[] hash, long timeStamp,
        String keyRingName) {
        NextlabsKeyId KEK = new NextlabsKeyId();
        KEK.setName(keyRingName);
        KEK.setHash(hash);
        KEK.setTimestamp(timeStamp);
        return KEK;
    }

    private KeyDTO getLatestKey(RandomAccessFile file, String keyRingName, String tenantId)
            throws Exception {
        KeyDTO k = null;
        try {
            k = com.nextlabs.keymanagement.KeyRetrievalManager.getInstance()
                    .getKey(KeyRetrievalManager.keyStorePassword, keyRingName, null, 0);
        } catch (KeyServiceSDKException e) {
            logger.error("Unable to get key:::", e);
            throw e;
        }
        return k;
    }
}
