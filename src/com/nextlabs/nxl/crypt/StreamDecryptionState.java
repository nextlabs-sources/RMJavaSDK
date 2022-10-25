package com.nextlabs.nxl.crypt;

/**
 * @author nnallagatla
 *
 */

import com.nextlabs.nxl.pojos.NXLFileMetaData;

public class StreamDecryptionState {

    private long contentLength;

    private String fileExtension;

    private byte[] headerContent;

    private NXLFileMetaData metaData;

    public StreamDecryptionState(long contentLength, String fileExtension, NXLFileMetaData metadata, byte[] headerBytes) {
        this.contentLength = contentLength;
        this.fileExtension = fileExtension;
        this.headerContent = headerBytes;
        this.metaData = metadata;
    }

    byte[] getHeaderContent() {
        return headerContent;
    }

    public long getContentLength() {
        return contentLength;
    }

    public String getFileExtension() {
        return fileExtension;
    }

    public NXLFileMetaData getNXLFileMetaData() {
        return metaData;
    }
}
