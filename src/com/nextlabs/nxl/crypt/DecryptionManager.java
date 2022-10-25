package com.nextlabs.nxl.crypt;

import com.nextlabs.nxl.exception.NXRTERROR;
import com.nextlabs.nxl.pojos.NXLFile;
import com.nextlabs.nxl.pojos.NXLFileMetaData;
import com.nextlabs.nxl.util.DecryptionUtil;

import java.io.File;
import java.io.RandomAccessFile;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class DecryptionManager {

    public static final String NXLFILE_EXTENSION = ".nxl";

    private static Logger logger = LoggerFactory.getLogger("DecryptionManager");

    private void validate(RandomAccessFile inputFile) throws Exception {
        if (!isNXL(inputFile)) {
            throw new NXRTERROR("The input file is not a NXL file.");
        }
    }

    static boolean isNXL(RandomAccessFile file) throws Exception {
        String nxlSignatureCode = DecryptionUtil.readUnsignedChar(file, 0, 8);
        if (!nxlSignatureCode.equals("NXLFMT!")) {
            return false;
        }
        return true;
    }

    NXLFile decryptFile(File inputFile, String outputPath, String tenantId) throws Exception {
        DecryptionHandler handler = new DecryptionHandler();
        RandomAccessFile inputRandomFile = new RandomAccessFile(inputFile, "r");
        boolean deleteOutputFile = true;
        try {
            validate(inputRandomFile);
            ConfigManager.getInstance().checkOutputFile(outputPath, ConfigManager.decrypt);
            NXLFile unwrappedFile = null;
            if (outputPath == null) {
                unwrappedFile = handler.parseContent(inputRandomFile, tenantId);
                unwrappedFile.setInMemory(true);
            }
            else {
                if (outputPath.endsWith(".nxl")) {
                    deleteOutputFile = false;
                    throw new NXRTERROR("The output file can't be an NXL file");
                }
                unwrappedFile = handler.parseContent(inputRandomFile, outputPath, tenantId);
            }
            deleteOutputFile = false;
            return unwrappedFile;
        } finally {
            IOUtils.closeQuietly(inputRandomFile);
            if (deleteOutputFile) {
                try {
                    File f = new File(outputPath);
                    f.delete();
                } catch (Exception e) {
                    logger.error("Can't delete corrupt output file", e);
                }
            }
        }
    }

    NXLFileMetaData readMeta(File inputFile) throws Exception {
        RandomAccessFile inputRandomFile = new RandomAccessFile(inputFile, "r");
        try {
            validate(inputRandomFile);
            DecryptionHandler handler = new DecryptionHandler();
            NXLFileMetaData meta = handler.readMeta(inputRandomFile);
            return meta;
        } finally {
            try {
                inputRandomFile.close();
            } catch (Exception e) {
                logger.error("Can't close RandomAccessFile", e);
            }
        }
    }
}
