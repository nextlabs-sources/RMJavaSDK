package com.nextlabs.nxl.pojos;

public class PolicyControllerDetails {

    private String keyStoreName;

    private String keyStorePassword;

    private String trustStoreName;

    private String trustStorePasswd;

    private String pcHostName;

    private int rmiPortNum;

    public String getKeyStoreName() {
        return keyStoreName;
    }

    public void setKeyStoreName(String keyStoreName) {
        this.keyStoreName = keyStoreName;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getTrustStoreName() {
        return trustStoreName;
    }

    public void setTrustStoreName(String trustStoreName) {
        this.trustStoreName = trustStoreName;
    }

    public String getTrustStorePasswd() {
        return trustStorePasswd;
    }

    public void setTrustStorePasswd(String trustStorePasswd) {
        this.trustStorePasswd = trustStorePasswd;
    }

    public String getPcHostName() {
        return pcHostName;
    }

    public void setPcHostName(String pcHostName) {
        this.pcHostName = pcHostName;
    }

    public int getRmiPortNum() {
        return rmiPortNum;
    }

    public void setRmiPortNum(int rmiPortNum) {
        this.rmiPortNum = rmiPortNum;
    }

}
