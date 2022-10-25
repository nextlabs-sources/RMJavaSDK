package com.nextlabs.nxl.pojos;

import java.util.List;
import java.util.Map;

public class NXLFileMetaData {

    public NXLFileMetaData(SectionTable sectionTable) {
        this.sectionTable = sectionTable;
    }

    public SectionTable getSectionTable() {
        return sectionTable;
    }

    private SectionTable sectionTable;

    /**
     * @return Map<String,String> This method returns the tags from the NXLFileMetaData object
     */
    public Map<String, List<String>> getTags() {
        return sectionTable.getSections()[2].getSectionData();
    }

    /**
     * @return Map<String,String> This method returns the rights from the NXLFileMetaData object
     */
    public Map<String, List<String>> getRights() {
        return (Map<String, List<String>>)sectionTable.getSections()[1].getSectionData();
    }

    /**
     * @return Map<String,String> This method returns the attributes from the NXLFileMetaData object
     */
    public Map<String, List<String>> getAttr() {
        return (Map<String, List<String>>)sectionTable.getSections()[0].getSectionData();
    }
}
