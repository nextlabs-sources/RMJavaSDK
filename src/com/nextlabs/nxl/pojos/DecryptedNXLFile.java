package com.nextlabs.nxl.pojos;

public class DecryptedNXLFile {

    private NXLHeaders nxlHeaders;

    private SectionTable sectionTable;

    private byte[] decryptedFile;

    public NXLHeaders getNxlHeaders() {
        return nxlHeaders;
    }

    public void setNxlHeaders(NXLHeaders nxlHeaders) {
        this.nxlHeaders = nxlHeaders;
    }

    public SectionTable getSectionTable() {
        return sectionTable;
    }

    public void setSectionTable(SectionTable sectionTable) {
        this.sectionTable = sectionTable;
    }

    public byte[] getDecryptedFile() {
        return decryptedFile;
    }

    public void setDecryptedFile(byte[] decryptedFile) {
        this.decryptedFile = decryptedFile;
    }
}
