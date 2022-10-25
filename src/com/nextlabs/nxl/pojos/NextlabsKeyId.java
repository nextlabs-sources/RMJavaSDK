package com.nextlabs.nxl.pojos;

public class NextlabsKeyId {

    private String name;
    /**< Key-ring Name */

    private byte[] hash;
    /**< Hash of this key */

    private long timestamp;

    /**< Key's creation time */

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getHash() {
        return hash;
    }

    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
}
