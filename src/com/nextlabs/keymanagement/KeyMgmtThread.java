package com.nextlabs.keymanagement;

import com.nextlabs.service.keyservice.IKey;

import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyMgmtThread implements Callable<IKey> {

    private static Logger logger = LoggerFactory.getLogger("KeyMgmtThread");

    private byte[] password;

    private String keyRingName;

    private byte[] keyId;

    private long timeStamp;
    
    private int retryCount = 0;

    public KeyMgmtThread(byte[] password, String keyRingName, byte[] keyId,
        long timeStamp) {
        this.password = password;
        this.keyRingName = keyRingName;
        this.keyId = keyId;
        this.timeStamp = timeStamp;
    }

    public KeyMgmtThread(byte[] password, String keyRingName) {
        this.password = password;
        this.keyRingName = keyRingName;
    }

    @Override
    public IKey call() throws Exception {
        //logger.debug("requesting for key..Thread id:"+Thread.currentThread().getId());
        logger.debug("requesting for key..Thread id:" + Thread.currentThread().getId());
        IKey key = null;
        try {
            if (keyId == null) {
                key = KeyRetrievalManager.getInstance().getKeyServiceClient().getKey(password, keyRingName);
            }
            else {
                key = KeyRetrievalManager.getInstance().getKeyServiceClient().getKey(password, keyRingName, keyId, timeStamp);
            }
        } catch (Exception e) {
            //logger.error("Error occurred while getting key", e);
            logger.error("Error occurred while getting key: ", e);
            if (e.getCause() != null && (e.getCause() instanceof java.rmi.ConnectException || e.getCause() instanceof java.rmi.NoSuchObjectException)) {
                //logger.info("Connection error..resetting keyServiceClient");
                logger.error("Connection error..resetting keyServiceClient");
                if (retryCount == 0) {
                    retryCount = 1;
                    KeyRetrievalManager.getInstance().resetKeyServiceClient();
                    key = call();
                } else {
                    throw e;
                }
            } else {
                throw e;
            }
        }
        //logger.debug("returning from getKey");
        return key;
    }
}
