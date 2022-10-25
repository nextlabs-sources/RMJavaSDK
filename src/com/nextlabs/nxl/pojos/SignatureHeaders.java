package com.nextlabs.nxl.pojos;

public class SignatureHeaders {

    private String nxlSignatureCode;

    private String message;

    public String getNxlSignatureCode() {
        return nxlSignatureCode;
    }

    public void setNxlSignatureCode(String nxlSignatureCode) {
        this.nxlSignatureCode = nxlSignatureCode;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

}
