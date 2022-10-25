package com.nextlabs.nxl.pojos;

public class NXLHeaders {

    private BasicHeaders basicHeaders;

    private CryptoHeaders cryptoHeaders;

    public BasicHeaders getBasicHeaders() {
        return basicHeaders;
    }

    public void setBasicHeaders(BasicHeaders basicHeaders) {
        this.basicHeaders = basicHeaders;
    }

    public CryptoHeaders getCryptoHeaders() {
        return cryptoHeaders;
    }

    public void setCryptoHeaders(CryptoHeaders cryptoHeaders) {
        this.cryptoHeaders = cryptoHeaders;
    }

    public SignatureHeaders getSignatureHeaders() {
        return signatureHeaders;
    }

    public void setSignatureHeaders(SignatureHeaders signatureHeaders) {
        this.signatureHeaders = signatureHeaders;
    }

    private SignatureHeaders signatureHeaders;

}
