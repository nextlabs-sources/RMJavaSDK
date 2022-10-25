package com.nextlabs.nxl.pojos;

public class NXLKeyBlob {

    public NXLKeKeyID getKeyID() {
        return NXLKeyID;
    }

    public void setKeyID(NXLKeKeyID keyID) {
        this.NXLKeyID = keyID;
    }

    public byte[] getCeKey() {
        return CeKey;
    }

    public void setCeKey(byte[] decryptedAESKeyArr) {
        CeKey = decryptedAESKeyArr;
    }

    private NXLKeKeyID NXLKeyID;

    private byte[] CeKey;

}
