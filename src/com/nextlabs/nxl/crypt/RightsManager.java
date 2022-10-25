package com.nextlabs.nxl.crypt;

import com.nextlabs.client.keyservice.KeyServiceSDKException;
import com.nextlabs.keymanagement.KeyRetrievalManager;
import com.nextlabs.kms.types.KeyDTO;
import com.nextlabs.nxl.Constants;
import com.nextlabs.nxl.exception.NXRTERROR;
import com.nextlabs.nxl.pojos.NXLFile;
import com.nextlabs.nxl.pojos.NXLFileMetaData;
import com.nextlabs.nxl.pojos.NXLSection;
import com.nextlabs.nxl.pojos.PolicyControllerDetails;
import com.nextlabs.nxl.pojos.SectionTable;
import com.nextlabs.nxl.util.DecryptionUtil;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class contains method to read meta data from an encrypted NXL file
 * ,to decrypt an NXL file and to encrypt an unprotected file. Only one instance
 * of this class should be created by the calling application as creating an instance
 * of this class is an expensive and time consuming task. The calling application can
 * perform multiple encryption/decryption operations on the same instance. Even in
 * multithreaded scenarios,create a single instance of RightsManager and share it
 * amongst different threads.This class is thread safe.Once the calling application has
 * completed all the operations, it must call the cleanup method to release any
 * memory being used by the API.
 *
 * @author psheoran
 * @version 1.0.7.1
 *
 */
public class RightsManager {

    private static Logger logger = LoggerFactory.getLogger("RightsManager");

    /**The RightsManager class connects to a KeyManagementService running on a Nextlabs'
     * Java Policy Controller. The communication between the Key Management Service and the
     * API is secured using password protected Keystore and Truststore files. Make sure you have
     * installed the Java Policy Controller and configured the Key Management Service on it.
     * Copy the keystore and truststore files from the Java Policy Controller to the system
     * running the API. The support for Key Management Server bundled with Control Center is being deprecated.
     * Consider using the new Key Management Server(KMS)
     * @param configFile	The configuration file contains properties required to initialize the the Right Manager class.
     * The configuration file must contain the following properties:<br/>
       KEY_STORE_NAME: The absolute path of the keystore file required for communicating with Key Management Service.
       You should have copied this file from the Java Policy Controller.<br/>
       KEY_STORE_PASSWORD: Password of the keystore file<br/>
       TRUST_STORE_NAME: The absolute path of the truststore file required for communicating with Key Management Service.
       You should have copied this file from the Java Policy Controller.<br/>
       TRUST_STORE_PASSWORD: Password of the truststore file.<br/>
       PC_HOST_NAME: Name or ip address of the Policy COntroller running Key Mananagement Service.<br/>
       RMI_PORT_NUM: Port on which the Policy Controller is running the Key Management Service.<br/>
     * @throws NXRTERROR
     */
    public RightsManager(File configFile) throws NXRTERROR {
        ConfigManager.getInstance().initialize(configFile);
        KeyRetrievalManager.getInstance().getKeyServiceClient();
    }

    /**The RightsManager class connects to a KeyManagementService running on a Nextlabs'
     * Java Policy Controller. The communication between the Key Management Service and the
     * API is secured using password protected Keystore and Truststore files. Make sure you have
     * installed the Java Policy Controller and configured the Key Management Service on it.
     * Copy the keystore and truststore files from the Java Policy Controller to the system
     * running the API. The support for Key Management Server bundled with Control Center is being deprecated.
     * Consider using the new Key Management Server(KMS)
     * @param policyControllerObject	The Policy Controller Object is a POJO that must contain all the
     * information required to establish communication between the API and the Key Management Service. The
     * calling must set all the field in the PolicyControllerDetails object using the setter methods, otherwise
     * the API will throw an exception.<br/>
     * The PolicyControllerDetails object contains the following fields:<br/>
       keyStoreName: The absolute path of the keystore file required for communicating with Key Management Service.
       You should have copied this file from the Java Policy Controller.<br/>
       keyStorePassword: Password of the keystore file<br/>
       trustStoreName: The absolute path of the truststore file required for communicating with Key Management Service.
       You should have copied this file from the Java Policy Controller.<br/>
       trustStorePassword: Password of the truststore file.<br/>
       pcHostName: Name or ip address of the Policy COntroller running Key Mananagement Service.<br/>
       rmiPortNum: Port on which the Policy Controller is running the Key Management Service.<br/>
     * @throws NXRTERROR
     */
    public RightsManager(PolicyControllerDetails policyControllerObject) throws NXRTERROR {
        if (policyControllerObject == null) {
            throw new NXRTERROR("The Policy Controller object can't be null");
        }
        ConfigManager.getInstance().initialize(policyControllerObject);
        KeyRetrievalManager.getInstance().getKeyServiceClient();
    }

    /**This method can be used to read all the meta data (tags, attributes and rights) associated with an NXL file.
     * @param inputPath  The absolute path of the NXL file whose meta data is to be read.
     * @return NxlFileMetaData: This class stores the tags, rights and attributes read from an NXL file.
     * @throws Exception
     */
    public NXLFileMetaData readMeta(String inputPath) throws Exception {
        File inputFile = new File(inputPath);
        return getMetaData(inputFile);
    }

    /**This method can be used to read all the meta data (tags, attributes and rights) associated with an NXL file.
     * @param inputFile  The NXL file whose meta data is to be read.
     * @return NxlFileMetaData: This class stores the tags, rights and attributes read from an NXL file.
     * @throws Exception
     */
    public NXLFileMetaData readMeta(File inputFile) throws Exception {
        return getMetaData(inputFile);
    }

    /**This method can be used to decrypt an NXL file. This method can be used in two different modes, based on the
     * value of the outputPath parameter. They are: <br/>
     * 1. If the outputPath is a valid string, the NXL file will be decrypted and written to the outputPath. If this
     * option is used, don't call getDecryptedBytes() method on the returned NXLFile object. Since the decrypted bytes
     * are not stored in this mode, an exception will be thrown if getDecryptedBytes() is called on the returned NxlFile
     * object.<br/>
     * 2. If the outputPath is null, the NXL file will be decrypted in-memory and will not written to the file system.
     * The calling application can read the decrypted bytes by calling the getDecryptedBytes() method on the returned
     * NXLFile object.This option is significantly slower than the previous option and keeps the decrypted bytes in-memory.
     * If the file size is big or multiple files are being decrypted at the same time using this option, an out of memory
     * exception may be thrown. This method shouldn't be used unless it's absolutely
     * necessary to keep the decrypted file in-memory.<br/>
     * @param inputPath The absolute path of the NXL file to decrypt
     * @param outputPath The absolute path of the file to write the decrypted file.
     * @return NxlFile: This class stores the metadata and decrypted bytes of the NXL file.
     * @throws Exception
     */
    @Deprecated
    public NXLFile decrypt(String inputPath, String outputPath) throws Exception {
        return decrypt(inputPath, outputPath, null);
    }

    /**This method can be used to decrypt an NXL file. This method can be used in two different modes, based on the
     * value of the outputPath parameter. They are: <br/>
     * 1. If the outputPath is a valid string, the NXL file will be decrypted and written to the outputPath. If this
     * option is used, don't call getDecryptedBytes() method on the returned NXLFile object. Since the decrypted bytes
     * are not stored in this mode, an exception will be thrown if getDecryptedBytes() is called on the returned NxlFile
     * object.<br/>
     * 2. If the outputPath is null, the NXL file will be decrypted in-memory and will not written to the file system.
     * The calling application can read the decrypted bytes by calling the getDecryptedBytes() method on the returned
     * NXLFile object.This option is significantly slower than the previous option and keeps the decrypted bytes in-memory.
     * If the file size is big or multiple files are being decrypted at the same time using this option, an out of memory
     * exception may be thrown. This method shouldn't be used unless it's absolutely
     * necessary to keep the decrypted file in-memory.<br/>
     * @param inputPath The absolute path of the NXL file to decrypt
     * @param outputPath The absolute path of the file to write the decrypted file.
     * @param tenantId TenantId of the tenant
     * @return NxlFile: This class stores the metadata and decrypted bytes of the NXL file.
     * @throws Exception
     */
    public NXLFile decrypt(String inputPath, String outputPath, String tenantId) throws Exception {
        DecryptionManager manager = null;
        NXLFile decryptedFile = null;
        try {
            File inputFile = new File(inputPath);
            manager = new DecryptionManager();
            decryptedFile = manager.decryptFile(inputFile, outputPath, tenantId);
        } catch (Exception e) {
            throw e;
        } finally {
            ConfigManager.getInstance().removeFromOutputSet(outputPath, ConfigManager.decrypt);
            if (manager != null) {
                manager = null;
            }
        }
        return decryptedFile;
    }

    /**This method can be used to decrypt an NXL file. This method can be used in two different modes, based on the
     * value of the outputPath parameter. They are: <br/>
     * 1. If the outputPath is a valid string, the NXL file will be decrypted and written to the outputPath. If this
     * option is used, don't call getDecryptedBytes() method on the returned NXLFile object. Since the decrypted bytes
     * are not stored in this mode, an exception will be thrown if getDecryptedBytes() is called on the returned NxlFile
     * object.<br/>
     * 2. If the outputPath is null, the NXL file will be decrypted in-memory and will not written to the file system.
     * The calling application can read the decrypted bytes by calling the getDecryptedBytes() method on the returned
     * NXLFile object.This option is significantly slower than the previous option and keeps the decrypted bytes in-memory.
     * If the file size is big or multiple files are being decrypted at the same time using this option, an out of memory
     * exception may be thrown. This method shouldn't be used unless it's absolutely
     * necessary to keep the decrypted file in-memory.<br/>
     * @param inputFile NXL file to be decrypted.
     * @param outputPath The absolute path of the file to write the decrypted file.
     * @return NxlFile: This class stores the metadata and decrypted bytes of the NXL file.
     * @throws Exception
     */
    @Deprecated
    public NXLFile decrypt(File inputFile, String outputPath) throws Exception {
        return decrypt(inputFile, outputPath, null);
    }

    /**This method can be used to decrypt an NXL file. This method can be used in two different modes, based on the
     * value of the outputPath parameter. They are: <br/>
     * 1. If the outputPath is a valid string, the NXL file will be decrypted and written to the outputPath. If this
     * option is used, don't call getDecryptedBytes() method on the returned NXLFile object. Since the decrypted bytes
     * are not stored in this mode, an exception will be thrown if getDecryptedBytes() is called on the returned NxlFile
     * object.<br/>
     * 2. If the outputPath is null, the NXL file will be decrypted in-memory and will not written to the file system.
     * The calling application can read the decrypted bytes by calling the getDecryptedBytes() method on the returned
     * NXLFile object.This option is significantly slower than the previous option and keeps the decrypted bytes in-memory.
     * If the file size is big or multiple files are being decrypted at the same time using this option, an out of memory
     * exception may be thrown. This method shouldn't be used unless it's absolutely
     * necessary to keep the decrypted file in-memory.<br/>
     * @param inputFile NXL file to be decrypted.
     * @param outputPath The absolute path of the file to write the decrypted file.
     * @return NxlFile: This class stores the metadata and decrypted bytes of the NXL file.
     * @param tenantId TenantId of the tenant
     * @throws Exception
     */
    public NXLFile decrypt(File inputFile, String outputPath, String tenantId) throws Exception {
        DecryptionManager manager = null;
        NXLFile decryptedFile = null;
        try {
            manager = new DecryptionManager();
            decryptedFile = manager.decryptFile(inputFile, outputPath, tenantId);
        } catch (Exception e) {
            throw e;
        } finally {
            ConfigManager.getInstance().removeFromOutputSet(outputPath, ConfigManager.decrypt);
            if (manager != null) {
                manager = null;
            }
        }
        return decryptedFile;
    }

    private NXLFileMetaData getMetaData(File inputFile)
            throws Exception {
        DecryptionManager manager = new DecryptionManager();
        NXLFileMetaData metadata = null;
        try {
            metadata = manager.readMeta(inputFile);
        } catch (Exception e) {
            throw e;
        }
        return metadata;
    }

    /**This method can be used to encrypt files and convert them to NXL format.
     * @param inputPath The path of the input file to be encrypted.
     * @param outputPath The path where the encrypted NXL file is written.
     * @param attributes Attributes to be added to the NXL file.
     * @param rights Rights to be added to the NXL file.
     * @param tags Tags to be added to the NXL file.
     * @throws Exception
     */
    @Deprecated
    public void encrypt(String inputPath, String outputPath, Map<String, List<String>> attributes,
        Map<String, List<String>> rights, Map<String, List<String>> tags) throws Exception {
        encrypt(inputPath, outputPath, attributes, rights, tags, null);
    }

    /**This method can be used to encrypt files and convert them to NXL format.
     * @param inputPath The path of the input file to be encrypted.
     * @param outputPath The path where the encrypted NXL file is written.
     * @param attributes Attributes to be added to the NXL file.
     * @param rights Rights to be added to the NXL file.
     * @param tags Tags to be added to the NXL file.
     * @param tenantId TenantId of the tenant
     * @throws Exception
     */
    public void encrypt(String inputPath, String outputPath, Map<String, List<String>> attributes,
        Map<String, List<String>> rights, Map<String, List<String>> tags, String tenantId) throws Exception {
        EncryptionManager manager = null;
        try {
            manager = new EncryptionManager();
            File inputFile = new File(inputPath);
            File outputFile = new File(outputPath);
            manager.encrypt(inputFile, outputFile, attributes, rights, tags, tenantId);
        } catch (Exception e) {
            throw e;
        } finally {
            ConfigManager.getInstance().removeFromOutputSet(outputPath, ConfigManager.encrypt);
            if (manager != null) {
                manager = null;
            }
        }
    }

    /**This method can be used to encrypt files and convert them to NXL format.
     * @param inputFile The input file to be encrypted.
     * @param outputFile The file where the encrypted NXL file will be written.
     * @param attributes Attributes to be added to the NXL file.
     * @param rights Rights to be added to the NXL file.
     * @param tags Tags to be added to the NXL file.
     * @throws Exception
     */
    @Deprecated
    public void encrypt(File inputFile, File outputFile, Map<String, List<String>> attributes,
        Map<String, List<String>> rights, Map<String, List<String>> tags) throws Exception {
        EncryptionManager manager = new EncryptionManager();
        manager.encrypt(inputFile, outputFile, attributes, rights, tags, null);
    }

    /**This method can be used to encrypt files and convert them to NXL format.
     * @param inputFile The input file to be encrypted.
     * @param outputFile The file where the encrypted NXL file will be written.
     * @param attributes Attributes to be added to the NXL file.
     * @param rights Rights to be added to the NXL file.
     * @param tags Tags to be added to the NXL file.
     * @param tenantId TenantId of the tenant
     * @throws Exception
     */
    public void encrypt(File inputFile, File outputFile, Map<String, List<String>> attributes,
        Map<String, List<String>> rights, Map<String, List<String>> tags, String tenantId) throws Exception {
        EncryptionManager manager = new EncryptionManager();
        manager.encrypt(inputFile, outputFile, attributes, rights, tags, tenantId);
    }

    /**This method can be used to read all the tags associated with an NXL file.
     * @param inputPath  The absolute path of the NXL file whose tags are to be read.
     * @return Map<String, List<String>>: Contains the tag name and the tag values.
     * @throws Exception
     */
    public Map<String, List<String>> readTags(String inputPath) throws Exception {
        return readMeta(inputPath).getTags();
    }

    /**This method can be used to read all the tags associated with an NXL file.
     * @param inputFile  The NXL file whose tags are to be read.
     * @return Map<String, List<String>>: Contains the tag name and the tag values.
     * @throws Exception
     */
    public Map<String, List<String>> readTags(File inputFile) throws Exception {
        return readMeta(inputFile).getTags();
    }

    /**This method can be used to read all the rights associated with an NXL file.
     * @param inputPath  The absolute path of the NXL file whose rights are to be read.
     * @return Map<String, List<String>>: Contains the rights name and the tag values.
     * @throws Exception
     */
    public Map<String, List<String>> readRights(String inputPath) throws Exception {
        return readMeta(inputPath).getRights();
    }

    /**This method can be used to read all the rights associated with an NXL file.
     * @param inputFile  The NXL file whose rights are to be read.
     * @return Map<String, List<String>>: Contains the rights name and the tag values.
     * @throws Exception
     */
    public Map<String, List<String>> readRights(File inputFile) throws Exception {
        return readMeta(inputFile).getRights();
    }

    /**This method can be used to read all the attributes associated with an NXL file.
     * @param inputPath  The absolute path of the NXL file whose attributes are to be read.
     * @return Map<String, List<String>>: Contains the attributes name and  values.
     * @throws Exception
     */
    public Map<String, List<String>> readAttributes(String inputPath) throws Exception {
        return readMeta(inputPath).getAttr();
    }

    /**This method can be used to read all the attributes associated with an NXL file.
     * @param inputFile  The NXL file whose attributes are to be read.
     * @return Map<String, List<String>>: Contains the attributes name and  values.
     * @throws Exception
     */
    public Map<String, List<String>> readAttributes(File inputFile) throws Exception {
        return readMeta(inputFile).getAttr();
    }

    /**This method must be called after you have finished using RightsManager.
     * KeyManagement service is active until this method is called.
     */
    @Deprecated
    public void cleanup() {
        //No cleanup required for new version 2 of key management
        if (ConfigManager.getInstance().getIntProperty(ConfigManager.KEY_MANAGEMENT_VERSION) == 1) {
            KeyRetrievalManager.getInstance().shutDown();
        }
    }

    /**This method can be used to change the Policy Controller settings after RightsManager has been intialized.
     * @param configFile	The configuration file contains properties required to initialize the the Right Manager class.
     */
    @Deprecated
    public void reloadConfig(File configFile) throws NXRTERROR {
        ConfigManager.getInstance().initialize(configFile);
        KeyRetrievalManager.getInstance().resetKeyServiceClient();
    }

    /**This method can be used to change the Policy Controller settings after RightsManager has been intialized.
     * @param policyControllerObject	The Policy Controller Object is a POJO that must contain all the
     * information required to establish communication between the API and the Key Management Service. The
     * calling must set all the field in the PolicyControllerDetails object using the setter methods, otherwise
     * the API will throw an exception.<br/>
     * The PolicyControllerDetails object contains the following fields:<br/>
       keyStoreName: The absolute path of the keystore file required for communicating with Key Management Service.
       You should have copied this file from the Java Policy Controller.<br/>
       keyStorePassword: Password of the keystore file<br/>
       trustStoreName: The absolute path of the truststore file required for communicating with Key Management Service.
       You should have copied this file from the Java Policy Controller.<br/>
       trustStorePassword: Password of the truststore file.<br/>
       pcHostName: Name or ip address of the Policy COntroller running Key Management Service.<br/>
       rmiPortNum: Port on which the Policy Controller is running the Key Management Service.<br/>
     */
    @Deprecated
    public void reloadConfig(PolicyControllerDetails pcObject) throws NXRTERROR {
        ConfigManager.getInstance().initialize(pcObject);
        KeyRetrievalManager.getInstance().resetKeyServiceClient();
    }

    /**This method can be used to change the KMS server URL after RightsManager has been intialized.
     * @param url		URL of the KMS server
     */
    public void reloadConfig(String url) throws NXRTERROR {
        ConfigManager.getInstance().initialize(url);
    }

    /**This method can be used to update tags on an encrypted NXL file without re-encrypting the file.
     * Take note that the older tags would be removed from the file permanently and only the new tags provided
     * to this method will exist on the file.
     * @param data		Contains new tags to be written to the file.
     * @param inputFile		Encrypted NXL file to be updated
     */
    @Deprecated
    public void updateTags(Map<String, List<String>> data, String inputPath) throws Exception {
        updateTags(data, inputPath, null);
    }

    /**This method can be used to update attributes of an encrypted NXL file without re-encrypting the file.
     * Take note that the older attributes would be removed from the file permanently and only the new attributes provided
     * to this method will exist on the file.
     * @param data		Contains new attributes to be written to the file.
     * @param inputPath		Path of the NXL file to be updated
     */
    @Deprecated
    public void updateAttributes(Map<String, List<String>> data, String inputPath) throws Exception {
        updateAttributes(data, inputPath, null);
    }

    /**This method can be used to update rights present in an encrypted NXL file without re-encrypting the file.
     * Take note that the older attributes would be removed from the file permanently and only the new attributes provided
     * to this method will exist on the file.
     * @param data		Contains new rights to be written to the file.
     * @param inputPath		Path of the NXL file to be updated
     */
    @Deprecated
    public void updateRights(Map<String, List<String>> data, String inputPath) throws Exception {
        updateRights(data, inputPath, null);
    }

    /**This method can be used to update tags on an encrypted NXL file without re-encrypting the file.
     * Take note that the older tags would be removed from the file permanently and only the new tags provided
     * to this method will exist on the file.
     * @param data		Contains new tags to be written to the file.
     * @param inputFile		Encrypted NXL file to be updated
     */
    @Deprecated
    public void updateTags(Map<String, List<String>> data, File inputFile) throws Exception {
        updateTags(data, inputFile, null);
    }

    /**This method can be used to update attributes of an encrypted NXL file without re-encrypting the file.
     * Take note that the older attributes would be removed from the file permanently and only the new attributes provided
     * to this method will exist on the file.
     * @param data		Contains new attributes to be written to the file.
     * @param inputFile		Encrypted NXL file to be updated
     */
    @Deprecated
    public void updateAttributes(Map<String, List<String>> data, File inputFile) throws Exception {
        updateAttributes(data, inputFile, null);
    }

    /**This method can be used to update rights present in an encrypted NXL file without re-encrypting the file.
     * Take note that the older attributes would be removed from the file permanently and only the new attributes provided
     * to this method will exist on the file.
     * @param data		Contains new rights to be written to the file.
     * @param inputFile		Encrypted NXL file to be updated
     */
    @Deprecated
    public void updateRights(Map<String, List<String>> data, File inputFile) throws Exception {
        updateRights(data, inputFile, null);
    }

    /**This method can be used to remove all tags present in an encrypted NXL file without re-encrypting the file.
     * @param inputPath		Path of the NXL file to be updated
     */
    @Deprecated
    public void removeTags(String inputPath) throws Exception {
        removeTags(inputPath, null);
    }

    /**This method can be used to remove all attributes present in an encrypted NXL file without re-encrypting the file.
     * @param inputPath		Path of the NXL file to be updated
     */
    @Deprecated
    public void removeAttributes(String inputPath) throws Exception {
        removeAttributes(inputPath, null);
    }

    /**This method can be used to remove all rights present in an encrypted NXL file without re-encrypting the file.
     * @param inputPath		Path of the NXL file to be updated
     */
    @Deprecated
    public void removeRights(String inputPath) throws Exception {
        removeRights(inputPath, null);
    }

    /**This method can be used to remove all tags present in an encrypted NXL file without re-encrypting the file.
     * @param inputFile		Encrypted NXL file to be updated
     */
    @Deprecated
    public void removeTags(File inputFile) throws Exception {
        removeTags(inputFile, null);
    }

    /**This method can be used to remove all attributes present in an encrypted NXL file without re-encrypting the file.
     * @param inputFile		Encrypted NXL file to be updated
     */
    @Deprecated
    public void removeAttributes(File inputFile) throws Exception {
        removeAttributes(inputFile, null);
    }

    /**This method can be used to remove all rights present in an encrypted NXL file without re-encrypting the file.
     * @param inputFile		Encrypted NXL file to be updated
     */
    @Deprecated
    public void removeRights(File inputFile) throws Exception {
        removeRights(inputFile, null);
    }

    /**This method can be used to update tags on an encrypted NXL file without re-encrypting the file.
     * Take note that the older tags would be removed from the file permanently and only the new tags provided
     * to this method will exist on the file.
     * @param data		Contains new tags to be written to the file.
     * @param inputPath		Path of the NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void updateTags(Map<String, List<String>> data, String inputPath, String tenantId) throws Exception {
        File inputFile = new File(inputPath);
        rewriteSection(2, data, inputFile, tenantId);
    }

    /**This method can be used to update attributes of an encrypted NXL file without re-encrypting the file.
     * Take note that the older attributes would be removed from the file permanently and only the new attributes provided
     * to this method will exist on the file.
     * @param data		Contains new attributes to be written to the file.
     * @param inputPath		Path of the NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void updateAttributes(Map<String, List<String>> data, String inputPath, String tenantId) throws Exception {
        File inputFile = new File(inputPath);
        rewriteSection(0, data, inputFile, tenantId);
    }

    /**This method can be used to update rights present in an encrypted NXL file without re-encrypting the file.
     * Take note that the older attributes would be removed from the file permanently and only the new attributes provided
     * to this method will exist on the file.
     * @param data		Contains new rights to be written to the file.
     * @param inputPath		Path of the NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void updateRights(Map<String, List<String>> data, String inputPath, String tenantId) throws Exception {
        File inputFile = new File(inputPath);
        rewriteSection(1, data, inputFile, tenantId);
    }

    /**This method can be used to update tags on an encrypted NXL file without re-encrypting the file.
     * Take note that the older tags would be removed from the file permanently and only the new tags provided
     * to this method will exist on the file.
     * @param data		Contains new tags to be written to the file.
     * @param inputFile		Encrypted NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void updateTags(Map<String, List<String>> data, File inputFile, String tenantId) throws Exception {
        rewriteSection(2, data, inputFile, tenantId);
    }

    /**This method can be used to update attributes of an encrypted NXL file without re-encrypting the file.
     * Take note that the older attributes would be removed from the file permanently and only the new attributes provided
     * to this method will exist on the file.
     * @param data		Contains new attributes to be written to the file.
     * @param inputFile		Encrypted NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void updateAttributes(Map<String, List<String>> data, File inputFile, String tenantId) throws Exception {
        rewriteSection(0, data, inputFile, tenantId);
    }

    /**This method can be used to update rights present in an encrypted NXL file without re-encrypting the file.
     * Take note that the older attributes would be removed from the file permanently and only the new attributes provided
     * to this method will exist on the file.
     * @param data		Contains new rights to be written to the file.
     * @param inputFile		Encrypted NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void updateRights(Map<String, List<String>> data, File inputFile, String tenantId) throws Exception {
        rewriteSection(1, data, inputFile, tenantId);
    }

    /**This method can be used to remove all tags present in an encrypted NXL file without re-encrypting the file.
     * @param inputPath		Path of the NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void removeTags(String inputPath, String tenantId) throws Exception {
        File inputFile = new File(inputPath);
        rewriteSection(2, new HashMap<String, List<String>>(), inputFile, tenantId);
    }

    /**This method can be used to remove all attributes present in an encrypted NXL file without re-encrypting the file.
     * @param inputPath		Path of the NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void removeAttributes(String inputPath, String tenantId) throws Exception {
        File inputFile = new File(inputPath);
        rewriteSection(0, new HashMap<String, List<String>>(), inputFile, tenantId);
    }

    /**This method can be used to remove all rights present in an encrypted NXL file without re-encrypting the file.
     * @param inputPath		Path of the NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void removeRights(String inputPath, String tenantId) throws Exception {
        File inputFile = new File(inputPath);
        rewriteSection(1, new HashMap<String, List<String>>(), inputFile, tenantId);
    }

    /**This method can be used to remove all tags present in an encrypted NXL file without re-encrypting the file.
     * @param inputFile		Encrypted NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void removeTags(File inputFile, String tenantId) throws Exception {
        rewriteSection(2, new HashMap<String, List<String>>(), inputFile, tenantId);
    }

    /**This method can be used to remove all attributes present in an encrypted NXL file without re-encrypting the file.
     * @param inputFile		Encrypted NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void removeAttributes(File inputFile, String tenantId) throws Exception {
        rewriteSection(0, new HashMap<String, List<String>>(), inputFile, tenantId);
    }

    /**This method can be used to remove all rights present in an encrypted NXL file without re-encrypting the file.
     * @param inputFile		Encrypted NXL file to be updated
     * @param tenantId TenantId of the tenant
     */
    public void removeRights(File inputFile, String tenantId) throws Exception {
        rewriteSection(1, new HashMap<String, List<String>>(), inputFile, tenantId);
    }

    /**This method can be used to find if a given file is an encrypted NXL file.
     * @param inputPath		Path of the file to be checked
     */
    public boolean isNXL(String inputPath) throws Exception {
        return isNXL(new File(inputPath));
    }

    /**This method can be used to find if a given file is an encrypted NXL file.
     * @param inputFile		File to be checked
     */
    public boolean isNXL(File inputFile) throws Exception {
        RandomAccessFile file = null;
        try {
            file = new RandomAccessFile(inputFile, "r");
            boolean nxl = DecryptionManager.isNXL(file);
            return nxl;
        } finally {
            try {
                file.close();
            } catch (Exception e) {
                logger.error("Couldn't close RandomAccessFile", e);
            }
        }
    }

    private void rewriteSection(int sectionNumber, Map<String, List<String>> data, File nxlFile, String tenantId)
            throws Exception {
        NXLFileMetaData metaData = readMeta(nxlFile);
        SectionTable sectionTable = metaData.getSectionTable();
        NXLSection[] sections = sectionTable.getSections();
        NXLSection section = sections[sectionNumber];
        section.setSectionData(data);
        EncryptionManager manager = new EncryptionManager();
        manager.rewriteSection(nxlFile, sectionNumber, sectionTable, tenantId);
    }

    /**This method can be used to check if the API is able to connect to the configured Policy Controller for key management.
     */
    public com.nextlabs.nxl.pojos.ConnectionResult testConnection() {
        KeyDTO k;
        KeyRetrievalManager instance = null;
        try {
            instance = com.nextlabs.keymanagement.KeyRetrievalManager.getInstance();
            k = instance.getKey(KeyRetrievalManager.keyStorePassword, EncryptionHandler.KEYRINGNAME_NL_SHARE, null, 0);
            return instance.getConnectionResultWrapper().getConnectionResult();
        } catch (KeyServiceSDKException e) {
            logger.error("Unable to get key:::", e);
        } catch (NXRTERROR e) {
            logger.error("Unable to get key:::", e);
        }
        return instance.getConnectionResultWrapper().getConnectionResult();
    }

    /**
     * Given size of a native file, this method returns the size of the NXL file
     * if the NXL file contains standard sections
     * @param contentSize
     *        Size of the native file in bytes
     * @return
     */
    public static long getStandardEncryptedContentSize(long contentSize) {
        return Constants.STANDARD_NXL_HEADER_SIZE + DecryptionUtil.roundToSize(
                contentSize, DecryptionUtil.NXL_PAGE_SIZE);
    }

    /**
     * This method reads from {@code in}, encrypts and writes encrypted bytes to {@code out}
     * @param in
     *        stream of native content
     * @param out
     *        stream where encrypted content will be written to
     * @param contentLength
     *        length of the native content in bytes
     * @param fileName
     *        File name for the native content
     * @param attributes
     *        Attributes to be stored in NXL file header
     * @param rights
     *        Rights to be stored in NXL file header
     * @param tags
     *        Tags to be stored in NXL file header
     * @param tenantId
     *        Id of the tenant. This determines the key that is used to encrypt the KEK
     * @throws Exception
     */
    public void encryptStream(InputStream in, OutputStream out, long contentLength, String fileName,
        Map<String, List<String>> attributes,
        Map<String, List<String>> rights, Map<String, List<String>> tags, String tenantId) throws Exception {
        EncryptionManager manager = new EncryptionManager();
        BufferedInputStream bIn = new BufferedInputStream(in);
        BufferedOutputStream bOut = new BufferedOutputStream(out);
        manager.encryptStream(bIn, bOut, contentLength, fileName, attributes, rights, tags, tenantId);
        bOut.flush();
    }

    /**
     * This method reads {@code contentLength} bytes from {@code in}, encrypts and writes encrypted bytes to {@code out}
     * @param in
     *        stream of native content
     * @param out
     *        stream where encrypted content will be written to
     * @param contentLength
     *        length of the native content
     * @param fileName
     *        File name for the native content
     * @param attributes
     *        Attributes to be stored in NXL file header
     * @param rights
     *        Rights to be stored in NXL file header
     * @param tags
     *        Tags to be stored in NXL file header
     * @throws Exception
     */
    public void encryptStream(InputStream in, OutputStream out, long contentLength, String fileName,
        Map<String, List<String>> attributes,
        Map<String, List<String>> rights, Map<String, List<String>> tags) throws Exception {
        encryptStream(in, out, contentLength, fileName, attributes, rights, tags, null);
    }

    /**
     *
     * @param header
     *        header content of the NXL file
     * @param tenantId
     *        id of the tenant
     * @return
     * @throws Exception
     */
    public StreamDecryptionState buildStreamDecryptionState(byte[] header, String tenantId) throws Exception {
        StreamDecryptionHandler handler = new StreamDecryptionHandler(header);
        return handler.getState();
    }

    /**
     *
     * @param in
     *        stream of NXL file starting at pointerOfContent
     * @param out
     *        decrypted content is written to this stream
     * @param state
     *        state constructed from the header content
     * @throws Exception
     */
    public void decryptStream(InputStream in, OutputStream out, StreamDecryptionState state) throws Exception {
        decryptStream(in, out, state, null);
    }

    /**
     *
     * @param in
     *        stream of NXL file starting at pointerOfContent
     * @param out
     *        decrypted content is written to this stream
     * @param tenantId
     *        id of the tenant
     * @param state
     *        state constructed from the header content
     * @throws Exception
     */
    public void decryptStream(InputStream in, OutputStream out, StreamDecryptionState state, String tenantId)
            throws Exception {
        BufferedInputStream bIn = new BufferedInputStream(in);
        BufferedOutputStream bOut = new BufferedOutputStream(out);
        StreamDecryptionHandler handler = new StreamDecryptionHandler(state.getHeaderContent());
        handler.decryptAndWriteFileContent(bIn, bOut, tenantId);
        bOut.flush();
    }
    
    /**
     * 
     * @param in
     *        stream of NXL file starting at pointerOfContent
     * @param out
     *        decrypted content is written to this stream
     * @param state
     *        state constructed from the header content
     * @param start
     *        index of first byte in range
     * @param len
     *        number of bytes to decrypt starting at start
     * @param skip
     *        true if 'in' has not skipped the bytes before 'start' 
     * @throws Exception
     */
    public void decryptPartial(InputStream in, OutputStream out, StreamDecryptionState state, long start, long len, boolean skip) throws Exception {
        BufferedInputStream bIn = new BufferedInputStream(in);
        BufferedOutputStream bOut = new BufferedOutputStream(out);
        StreamDecryptionHandler handler = new StreamDecryptionHandler(state.getHeaderContent());
        handler.decryptPartial(bIn, bOut, start, len, skip);
        bOut.flush();
    }
    
    /**
    * @param state
    *        state constructed from the header content
    */        
    public long getOriginalContentLength(StreamDecryptionState state) throws Exception{
        StreamDecryptionHandler handler = new StreamDecryptionHandler(state.getHeaderContent());
        return handler.getOriginalContentLength();
    }

    /**
     *
     * @param in
     *        stream of NXL file from beginning
     * @param out
     *        decrypted content is written to this stream
     * @throws Exception
     */
    public void parseAndDecryptStream(InputStream in, OutputStream out) throws Exception {
        parseAndDecryptStream(in, out, null);
    }

    /**
     *
     * @param in
     *        stream of NXL file from beginning
     * @param out
     *        decrypted content is written to this stream
     * @param tenantId
     *        id of the tenant
     * @throws Exception
     */
    public void parseAndDecryptStream(InputStream in, OutputStream out, String tenantId) throws Exception {
        byte[] header = new byte[getStandardNXLHeaderSize()];
        BufferedInputStream bIn = new BufferedInputStream(in);
        BufferedOutputStream bOut = new BufferedOutputStream(out);
        bIn.read(header);
        StreamDecryptionHandler handler = new StreamDecryptionHandler(header);
        handler.decryptAndWriteFileContent(bIn, bOut, tenantId);
        bOut.flush();
    }
    
    /**
     * 
     * @param in
     *        stream of NXL file from beginning
     * @param out
     *        decrypted content is written to this stream
     * @param start
     *        index of first byte in range
     * @param len
     *        number of bytes to decrypt starting at start
     * @param skip
     *        true if 'in' has not skipped the bytes before 'start' 
     * @throws Exception
     */
    public void parseAndDecryptPartial(InputStream in, OutputStream out, long start, long len, boolean skip) throws Exception {
        byte[] header = new byte[getStandardNXLHeaderSize()];
        BufferedInputStream bIn = new BufferedInputStream(in);
        BufferedOutputStream bOut = new BufferedOutputStream(out);
        bIn.read(header);
        StreamDecryptionHandler handler = new StreamDecryptionHandler(header);
        handler.decryptPartial(bIn, bOut, start, len, skip);
        bOut.flush();
    }
    

    /**
     * This method returns the size of NXL header with standard sections
     * @return
     */
    public static int getStandardNXLHeaderSize() {
        return Constants.STANDARD_NXL_HEADER_SIZE;
    }

}
