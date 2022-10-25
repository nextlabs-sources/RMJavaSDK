package com.nextlabs.nxl.crypt;

import com.nextlabs.nxl.exception.NXRTERROR;
import com.nextlabs.nxl.pojos.NXLSection;
import com.nextlabs.nxl.pojos.SectionTable;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class EncryptionManager {

    private static Logger logger = LoggerFactory.getLogger("EncryptionManager");

    private void validateInputFiles(String inputPath, String outputPath) throws NXRTERROR {
        if (inputPath == null) {
            throw new NXRTERROR("Input file path can't be null");
        }
        if (outputPath == null) {
            throw new NXRTERROR("Output file path can't be null");
        }
        if (inputPath.endsWith(".nxl")) {
            throw new NXRTERROR("Attempting to encrypt an NXL file.");
        }
        if (!outputPath.endsWith(".nxl")) {
            throw new NXRTERROR("The output path must be an NXL file");
        }
    }

    void encrypt(File inputFile, File outputFile, Map<String, List<String>> attributes,
        Map<String, List<String>> rights, Map<String, List<String>> tags, String tenantId) throws Exception {
        validateInputFiles(inputFile.getAbsolutePath(), outputFile.getAbsolutePath());
        if (!isSectionLengthValid(attributes, EncryptionHandler.ATTRIBUTES_LENGTH)) {
            throw new NXRTERROR("Attributes data exceeds the permissible size of attributes section. Remove some attributes and try again. The permissible limit is " + EncryptionHandler.ATTRIBUTES_LENGTH + " bytes");
        }
        if (!isSectionLengthValid(tags, EncryptionHandler.TAGS_LENGTH)) {
            throw new NXRTERROR("Tags data exceeds the permissible size of tags section. Remove some tags and try again. The permissible limit is " + EncryptionHandler.TAGS_LENGTH + " bytes");
        }
        if (!isSectionLengthValid(rights, EncryptionHandler.RIGHTS_LENGTH)) {
            throw new NXRTERROR("Rights data exceeds the permissible size of rights section. Remove some rights and try again later. The permissible limit is " + EncryptionHandler.RIGHTS_LENGTH + " bytes");
        }
        RandomAccessFile inputRandomFile = null;
        RandomAccessFile outputRandomFile = null;
        boolean deleteOutputFile = true;
        try {
            inputRandomFile = new RandomAccessFile(inputFile, "r");
            outputRandomFile = new RandomAccessFile(outputFile, "rw");
            EncryptionHandler handler = new EncryptionHandler();
            logger.info("Starting Encryption for " + inputFile.getAbsolutePath());
            handler.encrypt(inputRandomFile, outputRandomFile, inputFile.getName(), attributes, rights, tags, tenantId);
            deleteOutputFile = false;
            logger.info("Encryption completed for " + inputFile.getAbsolutePath());
        } finally {
            IOUtils.closeQuietly(inputRandomFile);
            IOUtils.closeQuietly(outputRandomFile);
            if (deleteOutputFile) {
                try {
                    outputFile.delete();
                } catch (Exception e) {
                    logger.error("Can't delete corrupt output file", e);
                }
            }
        }
    }

    void encryptStream(InputStream in, OutputStream out, long contentLength, String fileName,
        Map<String, List<String>> attributes,
        Map<String, List<String>> rights, Map<String, List<String>> tags, String tenantId) throws Exception {

        if (!isSectionLengthValid(attributes, EncryptionHandler.ATTRIBUTES_LENGTH)) {
            throw new NXRTERROR(
                    "Attributes data exceeds the permissible size of attributes section. Remove some attributes and try again. The permissible limit is "
                            + EncryptionHandler.ATTRIBUTES_LENGTH + " bytes");
        }
        if (!isSectionLengthValid(tags, EncryptionHandler.TAGS_LENGTH)) {
            throw new NXRTERROR(
                    "Tags data exceeds the permissible size of tags section. Remove some tags and try again. The permissible limit is "
                            + EncryptionHandler.TAGS_LENGTH + " bytes");
        }
        if (!isSectionLengthValid(rights, EncryptionHandler.RIGHTS_LENGTH)) {
            throw new NXRTERROR(
                    "Rights data exceeds the permissible size of rights section. Remove some rights and try again later. The permissible limit is "
                            + EncryptionHandler.RIGHTS_LENGTH + " bytes");
        }
        EncryptionHandler handler = new EncryptionHandler();
        handler.encryptStream(in, out, contentLength, fileName, attributes, rights, tags, tenantId);
    }

    void rewriteSection(File inputFile, int sectionNumber, SectionTable sectionTable, String tenantId) throws Exception {
        RandomAccessFile inputRandomFile = null;
        NXLSection[] sections = sectionTable.getSections();
        if (!isSectionLengthValid(sections[sectionNumber].getSectionData(), sections[sectionNumber].getSize())) {
            throw new NXRTERROR("Section data provided exceeds the permissible size of section. The permissible size of section is " + sections[sectionNumber].getSize() + " bytes");
        }
        try {
            inputRandomFile = new RandomAccessFile(inputFile, "rw");
            EncryptionHandler handler = new EncryptionHandler();
            handler.modifySection(inputRandomFile, sectionNumber, sectionTable, tenantId);
            inputRandomFile.close();
        } finally {
            try {
                inputRandomFile.close();
            } catch (Exception e) {
                logger.error("Can't close RandomAccessFile", e);
            }
        }
    }

    boolean isSectionLengthValid(Map<String, List<String>> sectionData, int sectionLength) {
        if (sectionData == null) {
            return true;
        }
        String sectionDataString = EncryptionHandler.getSectionDataString(sectionData);
        if (sectionDataString.length() * 2 > sectionLength) {
            return false;
        }
        return true;
    }
}
