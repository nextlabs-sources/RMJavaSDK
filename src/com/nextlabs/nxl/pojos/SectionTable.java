package com.nextlabs.nxl.pojos;

public class SectionTable {

    byte[] checksum;

    private int count;

    private NXLSection[] sections;

    public byte[] getChecksum() {
        return checksum;
    }

    public void setChecksum(byte[] checksum) {
        this.checksum = checksum;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public NXLSection[] getSections() {
        return sections;
    }

    public void setSections(NXLSection[] sections) {
        this.sections = sections;
    }
}
