package com.nextlabs.nxl.pojos;

import java.util.List;
import java.util.Map;

public class NXLSection {

    private String name;

    private int size;

    private int checksum;

    //This is not present in the C++ struct implementation
    Map<String, List<String>> sectionData;

    public Map<String, List<String>> getSectionData() {
        return sectionData;
    }

    public void setSectionData(Map<String, List<String>> attrMap) {
        this.sectionData = attrMap;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public int getChecksum() {
        return checksum;
    }

    public void setChecksum(int checksum) {
        this.checksum = checksum;
    }

}
