package com.nextlabs.nxl.test;

public class RoundToSize {

    public static void main(String[] args) {
        int length = 4100;
        int alignment = 4096;
        int result = (length + ((alignment) - 1)) & ~((alignment) - 1);
        System.out.println(result);
    }
}
