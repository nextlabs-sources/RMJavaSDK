package com.nextlabs.nxl.pojos;

public class CryptoHeaders {

    private int algorithm;

    private int cbcSize;

    private NXLKeyBlob primaryKey;

    private NXLKeyBlob recoveryKey;

    private long contentLength;

    private long allocateLength;

    private NXLPadding nxlPadding;

    public NXLPadding getNxlPadding() {
        return nxlPadding;
    }

    public void setNxlPadding(NXLPadding nxlPadding) {
        this.nxlPadding = nxlPadding;
    }

    public NXLKeyBlob getPrimaryKey() {
        return primaryKey;
    }

    public void setPrimaryKey(NXLKeyBlob primaryKey) {
        this.primaryKey = primaryKey;
    }

    public NXLKeyBlob getRecoveryKey() {
        return recoveryKey;
    }

    public void setRecoveryKey(NXLKeyBlob recoveryKey) {
        this.recoveryKey = recoveryKey;
    }

    public int getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(int algorithm) {
        this.algorithm = algorithm;
    }

    public int getCbcSize() {
        return cbcSize;
    }

    public void setCbcSize(int cbcSize) {
        this.cbcSize = cbcSize;
    }

    public long getContentLength() {
        return contentLength;
    }

    public void setContentLength(long contentLength) {
        this.contentLength = contentLength;
    }

    public long getAllocateLength() {
        return allocateLength;
    }

    public void setAllocateLength(long allocateLength) {
        this.allocateLength = allocateLength;
    }

}
