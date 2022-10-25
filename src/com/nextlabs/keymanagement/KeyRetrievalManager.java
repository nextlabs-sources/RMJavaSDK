package com.nextlabs.keymanagement;

import com.nextlabs.client.keyservice.KeyServiceSDK;
import com.nextlabs.client.keyservice.KeyServiceSDKException;
import com.nextlabs.kms.types.KeyDTO;
import com.nextlabs.kms.types.KeyIdDTO;
import com.nextlabs.nxl.exception.NXRTERROR;
import com.nextlabs.nxl.pojos.ConnectionResultWrapper;
import com.nextlabs.service.keyservice.IKey;

import java.util.HashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyRetrievalManager {

    private static KeyRetrievalManager instance = new KeyRetrievalManager();

    private ExecutorService executor;

    private KeyServiceSDK keyServiceClient = null;

    private HashMap<String, KeyDTO> cachedKeyMap = new HashMap<String, KeyDTO>();

    private ConnectionResultWrapper connectionResultWrapper;
    
    private static final Object LOCK = new Object();

    public static final byte[] keyStorePassword = new byte[] { 7, -117, 34, -79, -74, 85, -10, -63,
        -99, -120, 103, 15, -48, -46, -8, -88 };
    private static Logger logger = LoggerFactory.getLogger("KeyRetrievalManager");

    private KeyRetrievalManager() {
        connectionResultWrapper = new ConnectionResultWrapper();
        initKeyMgmtSDK();
    }

    public static KeyRetrievalManager getInstance() {
        return instance;
    }

    public KeyServiceSDK getKeyServiceClient() {
        if (keyServiceClient == null) {
            initKeyMgmtSDK();
        }
        return keyServiceClient;
    }

    public synchronized void initKeyMgmtSDK() {
        cachedKeyMap = new HashMap<String, KeyDTO>();
        KeyServiceSDKThread initializer = new KeyServiceSDKThread(connectionResultWrapper);
        executor = Executors.newFixedThreadPool(1);
        Future<KeyServiceSDK> res = executor.submit(initializer);
        try {
            keyServiceClient = res.get();
        } catch (Exception e) {
            logger.error("Exception while initializing Key Service SDK "
                    , e);
        }
    }

    public KeyDTO getKey(byte[] password, String keyRingName, byte[] keyId, long timeStamp)
            throws KeyServiceSDKException, NXRTERROR {
        IKey key = null;
        KeyDTO keyDTO = null;
        try {
            String mapKey = "";
            if (keyId != null && timeStamp != 0) {
                mapKey = keyRingName + new String(keyId) + timeStamp;
                if (cachedKeyMap != null) {
                    keyDTO = cachedKeyMap.get(mapKey);
                }
            }
            if (keyDTO != null) {
                return keyDTO;
            }
            synchronized(LOCK) {
                if (keyServiceClient == null) {
                    initKeyMgmtSDK();
                }
                if (keyServiceClient == null) {
                    throw new NXRTERROR("KeyManagement couldn't be initialized correctly.");
                }
                KeyMgmtThread thread = new KeyMgmtThread(password, keyRingName, keyId, timeStamp);
                ExecutorService executor = Executors.newFixedThreadPool(1);
                Future<IKey> res = executor.submit(thread);
                key = res.get();
                
                if (key == null) {
                    throw new NXRTERROR("Unable to retrieve key");
                }
                
                keyDTO = new KeyDTO();
                keyDTO.setKeyAlgorithm("AES");
                keyDTO.setKeyLength(256);
                keyDTO.setKeyValue(key.getEncoded());
                KeyIdDTO keyIdDTO = new KeyIdDTO();
                keyIdDTO.setHash(key.getId());
                keyIdDTO.setTimestamp(key.getCreationTimeStamp());
                keyDTO.setKeyId(keyIdDTO);
                if (keyId != null && timeStamp != 0) {
                    cachedKeyMap.put(mapKey, keyDTO);
                }
            }
        } catch (InterruptedException e) {
            logger.error("Exception occured while getting key \n", e);
        } catch (ExecutionException e) {
            logger.error("Exception occured while executing getKey call \n", e);
        }
        return keyDTO;
    }

    public void shutDown() {
        keyServiceClient = null;
        cachedKeyMap = null;
        executor.shutdownNow();
    }

    public void resetKeyServiceClient() {
        keyServiceClient = null;
        cachedKeyMap = null;
    }

    public ConnectionResultWrapper getConnectionResultWrapper() {
        return connectionResultWrapper;
    }

}
