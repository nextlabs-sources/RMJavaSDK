package com.nextlabs.nxl.crypt;

import com.nextlabs.nxl.exception.NXRTERROR;
import com.nextlabs.nxl.pojos.PolicyControllerDetails;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.ConcurrentSkipListSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigManager {

    private static final String version = "1.0.7.1";

    private static ConfigManager instance = new ConfigManager();

    public static final String KEY_STORE_NAME = "KEY_STORE_NAME";

    public static final String KEY_STORE_PASSWORD = "KEY_STORE_PASSWORD";

    public static final String TRUST_STORE_NAME = "TRUST_STORE_NAME";

    public static final String TRUST_STORE_PASSWORD = "TRUST_STORE_PASSWORD";

    public static final String PC_HOST_NAME = "PC_HOST_NAME";

    public static final String KMS_URL = "KMS_URL";

    public static final String KEY_MANAGEMENT_VERSION = "KEY_MANAGEMENT_VERSION";

    public static final String RMI_PORT_NUM = "RMI_PORT_NUM";

    public static final int decrypt = 0;

    public static final int encrypt = 1;

    public static final String UNTRUSTED_CERTIFICATE_VALUE = "MIIDfzCCAmegAwIBAgIEezATwTANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTETMBEGA1UEBxMKQ2FsaWZvcm5pYTERMA8GA1UEChMITmV4dGxhYnMxETAPBgNVBAsTCE5leHRsYWJzMREwDwYDVQQDEwhOZXh0bGFiczAeFw0xNjAxMTEwNTA5NDRaFw0yNjAxMDgwNTA5NDRaMHAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRMwEQYDVQQHEwpDYWxpZm9ybmlhMREwDwYDVQQKEwhOZXh0bGFiczERMA8GA1UECxMITmV4dGxhYnMxETAPBgNVBAMTCE5leHRsYWJzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtlh8euUmqDrcbXTRNYAOpfytS7TyBRXXjExZ+k+lAj/dxCZTvDirU90YVyze8hD8f5cbRb3/ZDENvFdGnjEKUY7A0fIdku6bmlqdCQwxhI3bWFk3d7G8ZWU9t5PjfSPo/XjQMDScw7CYqj02AYMIbbJiI6AFUiG5q49Gx0WAMfpskFsWfTra2L93OFN4U1c3euhWJhlP72GZI/Kswc9wBi/pi6rKkr213Qog2srgtAvh+MMKpjt4U6tCUJD0Gm1u8j7E1fbuAYFZhOI//C35SS70q4/snVT7YtxA3VIy5RaWc0Bct7N32xgqFsEiDziBfuv5tAouOuyfORmggyPAQQIDAQABoyEwHzAdBgNVHQ4EFgQUyehM/ZFgpAokDNMrQcYnH4oaV2IwDQYJKoZIhvcNAQELBQADggEBAEd8W/Gum1EJcT0RA7lHIS/5Dbxuvmjdvn95EIP6XWY1Hte7KJdIudFRk8p/iN5eE1YicEF3x3dZ61x2VvMzLwpMzmLj9wbdoEYF7l71bdE2+ROK4qs9JvFn+rGu7AxsrOhjBPUA37OZtK6hCorpWwUSR4c9MfmWkOBvQrmezvu4K8Q6Mf+djHRcBGVvPWQk/eYJ0SJjNPSQ63LFLEJv7QVGlrtIleAzHDmtqrgismT7ulcrayR51I/2f4KtXSLEOwqBUbDJtYWvIVO+o4hslYwNThVPce9h9GoH4zallaUpyVwF45eaeDa4Is/XmrfvqWzBkNq4WVKVNLCsupaBMt8=";

    public static final String WEBSVC_CERTIFICATE_NAME = "X-AUTH-CERT";

    public static final String WEBSVC_SECURE_CERTIFICATE_NAME = "X-NXL-S-CERT";

    private ConcurrentSkipListSet<String> decryptionSet;

    private ConcurrentSkipListSet<String> encryptionSet;

    private Properties properties = new Properties();

    private static Logger logger;

    private ConfigManager() {
        logger = LoggerFactory.getLogger("ConfigManager");
        decryptionSet = new ConcurrentSkipListSet<String>();
        encryptionSet = new ConcurrentSkipListSet<String>();
        logger.info("ConfigManager Created");
    }

    synchronized void initialize(File propertiesFile) throws NXRTERROR {
        BufferedInputStream inStream = null;
        /*if (!configPath.equals(propertiesFilePath) && configPath.length() > 0) {
        	throw new NXRTERROR(
        			"The policy controller settings have already been initialzed by file "
        					+ configPath + ". It can't be initialized again.");
        }*/
        try {
            inStream = new BufferedInputStream(new FileInputStream(propertiesFile));
            properties.load(inStream);
            properties.setProperty(KEY_MANAGEMENT_VERSION, 1 + "");
        } catch (IOException e) {
            throw new NXRTERROR("Error occured while reading config file");
        } finally {
            try {
                if (inStream != null) {
                    inStream.close();
                }
            } catch (IOException e) {
                logger.error("Error occurred while closing stream", e);
            }
        }
        validate();
    }

    synchronized void initialize(PolicyControllerDetails pcObject)
            throws NXRTERROR {
        properties.setProperty(KEY_MANAGEMENT_VERSION, 1 + "");
        properties.setProperty(KEY_STORE_NAME, pcObject.getKeyStoreName());
        properties.setProperty(KEY_STORE_PASSWORD,
                pcObject.getKeyStorePassword());
        properties.setProperty(TRUST_STORE_NAME, pcObject.getTrustStoreName());
        properties.setProperty(TRUST_STORE_PASSWORD,
                pcObject.getTrustStorePasswd());
        properties.setProperty(PC_HOST_NAME, pcObject.getPcHostName());
        properties.setProperty(RMI_PORT_NUM, pcObject.getRmiPortNum() + "");
        validate();
    }

    synchronized void initialize(String url) throws NXRTERROR {
        properties.setProperty(KEY_MANAGEMENT_VERSION, "2");
        properties.setProperty(KMS_URL, url);
    }

    void removeFromOutputSet(String path, int mode) throws NXRTERROR {
        if (mode == decrypt && path != null) {
            decryptionSet.remove(path);
        } else if (mode == encrypt && path != null) {
            encryptionSet.remove(path);
        }
    }

    public void checkOutputFile(String outputPath, int mode) throws NXRTERROR {
        if (outputPath == null) {
            return;
        }
        if (mode == decrypt) {
            if (decryptionSet.contains(outputPath)) {
                throw new NXRTERROR("The output file is already in use.");
            } else {
                decryptionSet.add(outputPath);
            }
        } else if (mode == encrypt) {
            if (encryptionSet.contains(outputPath)) {
                throw new NXRTERROR("The output file is already in use.");
            } else {
                encryptionSet.add(outputPath);
            }
        } else {
            throw new NXRTERROR("Unsupported mode passed to ConfigManager");
        }
    }

    private void validate() throws NXRTERROR {
        if (properties.getProperty(KEY_STORE_NAME) == null
                || properties.getProperty(KEY_STORE_NAME).length() == 0
                || properties.getProperty(KEY_STORE_PASSWORD) == null
                || properties.getProperty(KEY_STORE_PASSWORD).length() == 0
                || properties.getProperty(TRUST_STORE_NAME) == null
                || properties.getProperty(TRUST_STORE_NAME).length() == 0
                || properties.getProperty(TRUST_STORE_PASSWORD) == null
                || properties.getProperty(TRUST_STORE_PASSWORD).length() == 0
                || properties.getProperty(PC_HOST_NAME) == null
                || properties.getProperty(PC_HOST_NAME).length() == 0
                || properties.getProperty(RMI_PORT_NUM) == null
                || properties.getProperty(RMI_PORT_NUM).length() == 0) {
            throw new NXRTERROR("Policy Controller details not set correctly");
        }
    }

    public static ConfigManager getInstance() {
        return instance;
    }

    public boolean getBooleanProperty(String key) {
        String val = properties.getProperty(key);
        if (val == null) {
            return false;
        }
        if (val.trim().equalsIgnoreCase("true")
                || val.trim().equalsIgnoreCase("yes")) {
            return true;
        }
        return false;
    }

    public String getStringProperty(String key) {
        String val = properties.getProperty(key, "").trim();
        return val;
    }

    public int getIntProperty(String key) {
        int val = -1;
        try {
            String strVal = properties.getProperty(key);
            if (strVal != null && strVal.length() > 0) {
                val = Integer.parseInt(strVal.trim());
            }
            return val;
        } catch (Exception e) {
            logger.error("Error occurred while getting value for key:"
                    + key);
            return val;
        }
    }

    public long getLongProperty(String key) {
        long val = -1;
        try {
            String strVal = properties.getProperty(key);
            if (strVal != null && strVal.length() > 0) {
                val = Long.parseLong(strVal.trim());
            }
            return val;
        } catch (Exception e) {
            logger.error("Error occurred while getting value for key:"
                    + key);
            return val;
        }
    }

    public static void main(String args) {
        getVersion();
    }

    public static void getVersion() {
        System.out.println("Version of RMJavaSDK:" + version);
    }
}
