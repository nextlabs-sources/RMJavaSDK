package com.nextlabs.nxl.pojos;

public class BasicHeaders {

    private char[] thumbPrint;

    private short minVersion;

    private short majVersion;

    private int flags;

    private int alignment;

    private int pointerOfContent;

    public char[] getThumbPrint() {
        return thumbPrint;
    }

    public void setThumbPrint(char[] thumbPrint) {
        this.thumbPrint = thumbPrint;
    }

    public short getMinVersion() {
        return minVersion;
    }

    public void setMinVersion(short minVersion) {
        this.minVersion = minVersion;
    }

    public short getMajVersion() {
        return majVersion;
    }

    public void setMajVersion(short majVersion) {
        this.majVersion = majVersion;
    }

    public int getFlags() {
        return flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public int getAlignment() {
        return alignment;
    }

    public void setAlignment(int alignment) {
        this.alignment = alignment;
    }

    public int getPointerOfContent() {
        return pointerOfContent;
    }

    public void setPointerOfContent(int pointerOfContent) {
        this.pointerOfContent = pointerOfContent;
    }

}
