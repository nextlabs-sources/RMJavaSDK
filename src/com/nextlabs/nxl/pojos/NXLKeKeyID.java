package com.nextlabs.nxl.pojos;

public class NXLKeKeyID {

    private short algorithm;

    private short idSize;

    private byte[] id;

    private NextlabsKeyId nextlabsKeyId;

    public NextlabsKeyId getNextlabsKeyId() {
        return nextlabsKeyId;
    }

    public void setNextlabsKeyId(NextlabsKeyId keyId) {
        this.nextlabsKeyId = keyId;
    }

    public short getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(short algorithm) {
        this.algorithm = algorithm;
    }

    public short getIdSize() {
        return idSize;
    }

    public void setIdSize(short idSize) {
        this.idSize = idSize;
    }

    public byte[] getId() {
        return id;
    }

    public void setId(byte[] id) {
        this.id = id;
    }

}
