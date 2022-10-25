package com.nextlabs.nxl.test;

public class FormatKey {

    public static void main(String[] args) {
        String KEK = "F667AE62F1DFFBDCBB54855F9D6B130B169916E8097CE1C3F08CD7E67BA91B60";
        String formattedKEK = "";
        for (int i = 0; i < KEK.length(); i = i + 2) {
            formattedKEK += "(byte)0x" + KEK.charAt(i) + KEK.charAt(i + 1) + ",";
        }
        System.out.println("KEK is : \n " + formattedKEK);
    }
}
