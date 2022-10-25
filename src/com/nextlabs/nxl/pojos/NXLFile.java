package com.nextlabs.nxl.pojos;

import com.nextlabs.nxl.exception.NXRTERROR;

public class NXLFile {

    private boolean inMemory;

    private byte[][] decryptedBytes;

    private NXLFileMetaData metaData;

    /**
     * @return Returns the NxlFileMetaData object that stores the tags, rights and attributes
     */
    public NXLFileMetaData getMetaData() {
        return metaData;
    }

    public void setMetaData(NXLFileMetaData metaData) {
        this.metaData = metaData;
    }

    /**
     * @return Returns the decrypted file content in a 2 dimensional byte array
     * @throws NXRTERROR
     */
    public byte[][] getDecryptedBytes() throws NXRTERROR {
        if (!isInMemory()) {
            throw new NXRTERROR("The decrypted bytes were written to the file system and were not stored in memory for future reference.");
        }
        return decryptedBytes;
    }

    public void setDecryptedBytes(byte[][] decryptedBytes) {
        this.decryptedBytes = decryptedBytes;
    }

    public boolean isInMemory() {
        return inMemory;
    }

    public void setInMemory(boolean inMemory) {
        this.inMemory = inMemory;
    }

}
