package com.nextlabs.nxl.test;

public class KeyTest {

    public static void main(String[] args) {
        byte[] pcKey = { 83, -114, 30, 14, -64, 97, 82, 36, 20, 56, 115, -63, 89, 50, -95, -106, -18, 120, 8, 99, 99,
            47, 63, -15, 96, -43, -91, -118, 85, -50, 15, 44 };
        byte[] aesKey = { 112, -112, 14, 78, -54, 16, 110, 69, 51, 25, 112, 91, 87, -18, -120, 114, 2, -37, -67, 18,
            -36, 14, 107, 20, -61, -3, 82, -74, -25, 15, -4, 64, -104, 80, -58, -17, -90, 83, -44, -30, 83, -94, 110,
            -121, 16, 83, -30, 10, 108, 22, 117, 85, 99, -99, 12, -15, -32, -32, -48, 122, -24, -91, -117, 56, -35, 99,
            -10, -45, 87, 123, 8, 87, -84, -91, -35, -78, 20, 91, -115, 110, 1, -84, -42, 95, 26, -65, -20, 15, -41,
            108, 120, 46, 8, -101, 76, 61, -115, 30, 89, 125, 87, -63, -91, -23, 45, -104, -53, 100, -4, -89, 98, -89,
            58, 94, -65, 43, -106, 52, -16, 92, -58, -16, -88, -84, -42, 10, -63, -120, 45, -54, -78, -36, -95, -18,
            -16, 41, 38, -79, 12, -56, -59, 8, -74, 73, -39, -59, 37, -101, -1, -8, -117, 110, 37, -106, 84, -119, 92,
            -86, -120, 1, -68, 71, 40, 0, -115, 16, 101, 82, -75, -24, -12, 0, -48, -107, -122, 66, -11, -18, 19, -68,
            -117, 33, -112, 17, -28, -94, -117, 108, 18, 11, 14, -23, 110, -66, 0, 59, -98, 89, 114, -99, 43, -65, 85,
            42, 41, 115, 89, -46, -87, -38, 50, -46, -10, -89, -111, 81, -6, -121, 26, 13, -87, -25, 93, -30, 101,
            -126, 111, 49, -51, 58, -110, -2, 36, 119, -28, 8, 70, 32, -123, -99, 16, 37, -94, 11, -23, 122, 113, 39,
            65, 77, 118, -63, -54, -116, 23, 86 };
        byte[] decryptedKey = { 20, 7, 12, 20, -99, -1, 82, -50, -118, -88, 26, -38, 4, 58, -12, 73, -8, -47, -46, -3,
            35, -15, -71, 14, -20, -42, -61, 126, -104, -37, -65, 127, 80, 59, -85, -75, -83, 98, 46, -49, 102, 21,
            116, 119, 107, -4, 123, -87, -29, -40, 100, -83, 76, 80, 31, 74, 76, -105, 18, 93, -68, 74, 72, -109, -3,
            -74, -56, -87, 61, 107, -48, -86, -121, -53, 50, -17, -96, 47, 43, 33, 20, 89, 17, -24, -100, -111, 64, -6,
            -2, -38, 32, -103, -49, -43, 50, 26, 35, 102, 126, 41, 59, -51, 4, 58, 73, -65, -116, 62, -95, -13, -60,
            39, 16, 111, 45, 48, 21, -55, 68, 71, 81, 99, 73, -99, -81, 5, -6, 26, -124, 121, 110, 14, 118, 59, -124,
            -99, -109, -50, -4, 23, 47, -35, 75, -28, -48, -43, -121, 114, 22, 102, -56, -106, -86, 86, 105, 115, -67,
            -31, 30, -15, 118, 96, 102, -17, -50, 83, 57, 27, 3, -16, 15, -65, 41, -109, 8, -99, 66, -64, -99, 5, -43,
            6, -65, 2, -19, -13, -91, -34, 85, 111, 26, 51, 34, -31, -87, -21, -121, 6, -121, -90, 112, 83, 27, -60,
            27, 124, 2, -26, -81, 126, 104, -117, -91, -106, 118, 113, -66, 25, 104, 73, 53, -14, 28, 10, 58, -120,
            -57, -23, -51, 59, 125, -10, 16, -58, 123, 93, -115, -113, -96, 90, -39, -75, -13, 49, 114, 63, -102, -9,
            -23, -71, -125, -73, 35, -107, 35, 0 };
        byte[] aesKey32 = new byte[32];
        byte[] decryptedKey32 = new byte[32];
        byte[] content = { 32, 84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 110, 101, 120, 116, 108, 97, 98, 115, 32,
            112, 114, 111, 116, 101, 99, 116, 101, 100, 32, 102, 105, 108, 101, 32, 32, 84, 104, 105, 115, 32, 105,
            115, 32, 97, 32, 110, 101, 120, 116, 108, 97, 98, 115, 32, 112, 114, 111, 116, 101, 99, 116, 101, 100, 127,
            63, 92, 87, -50, 19, 113, 95, -29, 2, 27, -22, 84, 125 };
        byte[] hash = { -40, -90, 7, -33, -79, -62, 112, 31, 100, -66, -3, -12, -120, -36, 9, 10, -2, 115, 97, -79, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        System.arraycopy(aesKey, 0, aesKey32, 0, 32);
        System.arraycopy(decryptedKey, 0, decryptedKey32, 0, 32);
        System.out.println(toHex(pcKey));
        System.out.println(toHex(aesKey32));
        System.out.println(toHex(decryptedKey32));
        System.out.println(toHex(content));
        toHex(hash);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
            System.out.print("0x" + String.format("%02x", b) + ", ");
        }
        System.out.println();
        return sb.toString();
    }
}
