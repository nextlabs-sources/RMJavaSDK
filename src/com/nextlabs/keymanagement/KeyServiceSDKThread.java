package com.nextlabs.keymanagement;

import com.nextlabs.client.keyservice.KeyServiceSDK;
import com.nextlabs.nxl.crypt.ConfigManager;
import com.nextlabs.nxl.exception.NXRTERROR;
import com.nextlabs.nxl.pojos.ConnectionResult;
import com.nextlabs.nxl.pojos.ConnectionResultWrapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyServiceSDKThread implements Callable<KeyServiceSDK> {

    private static Logger log = LoggerFactory.getLogger("KeyServiceSDKThread");
    ConnectionResultWrapper connectionResultWrapper;

    public KeyServiceSDKThread(ConnectionResultWrapper connectionResultWrapper) {
        this.connectionResultWrapper = connectionResultWrapper;
    }

    @Override
    public KeyServiceSDK call() throws Exception {
        KeyServiceSDK keyServiceClient = null;
        try {
            String keyStoreName = ConfigManager.getInstance().getStringProperty("KEY_STORE_NAME");
            String keyStorePasswd = ConfigManager.getInstance().getStringProperty("KEY_STORE_PASSWORD");
            String trustStoreName = ConfigManager.getInstance().getStringProperty("TRUST_STORE_NAME");
            String trustStorePasswd = ConfigManager.getInstance().getStringProperty("TRUST_STORE_PASSWORD");
            String pcHostName = ConfigManager.getInstance().getStringProperty("PC_HOST_NAME");
            //Validate the keystore files
            if (!validateCert(keyStoreName, keyStorePasswd) || !validateCert(trustStoreName, trustStorePasswd)) {
                connectionResultWrapper.setConnectionResult(ConnectionResult.CERTIFICATE_ERROR);
                throw new NXRTERROR("KeyManagement couldn't be initialized due to certificate error");
            }
            if (pcHostName == null || pcHostName.length() == 0) {
                pcHostName = "localhost";// Try localhost if PC is not configured
            }
            log.info("About to initialize KeyServiceSDK..Thread id:"
                    + Thread.currentThread().getId());
            if (keyStoreName == null || keyStorePasswd == null || trustStoreName == null || trustStorePasswd == null) {
                connectionResultWrapper.setConnectionResult(ConnectionResult.MISSING_CONFIGURATION_ERROR);
                throw new NXRTERROR("KeyManagement couldn't be initialized due to missing configuration property");
            }
            int rmiPortNum = ConfigManager.getInstance().getIntProperty("RMI_PORT_NUM");
            keyServiceClient = new KeyServiceSDK(pcHostName,
                    keyStoreName, keyStorePasswd, trustStoreName,
                    trustStorePasswd, rmiPortNum);
            log.info("KeyServiceSDK initialized");
            connectionResultWrapper.setConnectionResult(ConnectionResult.SUCCESS);
        } catch (NXRTERROR ex) {
            log.error("Error occurred while initializing Key Service SDK", ex);
        } catch (Throwable e) {
            connectionResultWrapper.setConnectionResult(ConnectionResult.CONNECTION_ERROR);
            log.error("Error occurred while initializing Key Service SDK", e);
        }
        return keyServiceClient;
    }

    private boolean validateCert(String keyStoreName, String keyStorePasswd) {
        FileInputStream is = null;
        try {
            File file = new File(keyStoreName);
            is = new FileInputStream(file);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, keyStorePasswd.toCharArray());
        } catch (Exception e) {
            log.error("Exception occured while opening the certificate file", e);
            return false;
        } finally {
            if (null != is)
                try {
                    is.close();
                } catch (IOException e) {
                    log.error("Couldn't close the stream", e);
                }
        }
        return true;
    }
};
