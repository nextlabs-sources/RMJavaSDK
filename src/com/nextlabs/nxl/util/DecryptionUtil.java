package com.nextlabs.nxl.util;

import com.nextlabs.nxl.exception.NXRTERROR;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.nio.ShortBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

public class DecryptionUtil {

    public static final String NXL_SIGNATURE = "NXLFMT!";

    public static final int NXL_MAJOR_VERSION_10 = 0x0001;
    /**< NXL Format Version 1.0 */

    public static final int NXL_MINOR_VERSION_10 = 0x0000;
    /**< NXL Format Minor Version 0.0 */

    public static final int NXL_PAGE_SIZE = 4096;

    public static final int NXL_CBC_SIZE = 0x200;
    /**< NXL Format CBC Size */

    public static final int NXL_MIN_SIZE = 0x3000;
    /**< NXL Format Minimum File Size */

    public static final int NX_CEK_MAX_LEN = 256;
    /**< Maximum Content Encrypt Key Size */

    public static final int NX_KEK_MAX_LEN = 512;
    /**< Maximum Key Encrypt Key Size */

    public static final int MAX_SECTION_COUNT = 72;
    /**< Maximum section count */

    public static final int NXL_FLAGS_NONE = 0x00000000;
    /**< NXL Format File Flag: None */

    public static final int NXL_CRYPTO_FLAGS_NONE = 0x00000000;
    /**< NXL Format Crypto Flag: None */

    public static final String NXL_DEFAULT_MSG = "This is a NXL File!";
    /**< NXL Format default message */

    public static final String NXL_SECTION_ATTRIBUTES = ".Attrs";
    /**< Name of default section "Attributes" */

    public static final String NXL_SECTION_RIGHTS = ".Rights";
    /**< Name of default section "Rights" */

    public static final String NXL_SECTION_TAGS = ".Tags";
    /**< Name of default section "Tags" */

    public static final int NXL_ALGORITHM_NONE = 0;
    /**< No algorithm (No encrypted) */

    public static final int NXL_ALGORITHM_AES128 = 1;
    /**< AES 128 bits */

    public static final int NXL_ALGORITHM_AES256 = 2;
    /**< AES 256 bits (Default content encryption algorithm) */

    public static final int NXL_ALGORITHM_RSA1024 = 3;
    /**< RSA 1024 bits */

    public static final int NXL_ALGORITHM_RSA2048 = 4;
    /**< RSA 2048 bits */

    public static final int NXL_ALGORITHM_SHA1 = 5;
    /**< SHA1 (Default hash algorithm) */

    public static final int NXL_ALGORITHM_SHA256 = 6;
    /**< SHA256 */

    public static final int NXL_ALGORITHM_MD = 7;

    /**< MD5 */

    public static int roundToSize(int length, int alignment) {
        return (length + ((alignment) - 1)) & ~((alignment) - 1);
    }

    public static long roundToSize(long length, int alignment) {
        return (length + ((alignment) - 1)) & ~((alignment) - 1);
    }

    /*public static String toHex(byte[] bytes) {
    	StringBuilder sb = new StringBuilder();
    	for (byte b : bytes) {
    		sb.append(String.format("%02x", b));
    		System.out.print("0x"+String.format("%02x", b)+", ");
    	}
    	System.out.println();
    	return sb.toString();
    }*/

    public static byte[] readBytes(RandomAccessFile file, long offset, int numBytes)
            throws Exception {
        byte[] recordBuffer = new byte[numBytes];
        file.seek(offset);
        file.read(recordBuffer);
        return recordBuffer;
    }

    public static int readInt(RandomAccessFile file, int offset, int numBytes)
            throws Exception {
        byte[] recordBuffer = new byte[numBytes];
        ByteBuffer record = ByteBuffer.wrap(recordBuffer);
        record.order(ByteOrder.LITTLE_ENDIAN);
        IntBuffer intRecordBuffer = record.asIntBuffer();
        file.seek(offset);
        file.read(recordBuffer);
        int intVal = intRecordBuffer.get();
        return intVal;
    }

    public static short readShort(RandomAccessFile file, int offset, int numBytes)
            throws Exception {
        byte[] recordBuffer = new byte[numBytes];
        ByteBuffer record = ByteBuffer.wrap(recordBuffer);
        record.order(ByteOrder.LITTLE_ENDIAN);
        ShortBuffer shortRecordBuffer = record.asShortBuffer();
        file.seek(offset);
        file.read(recordBuffer);
        short shortVal = shortRecordBuffer.get();
        return shortVal;
    }

    public static long readLong(RandomAccessFile file, int offset, int numBytes)
            throws Exception {
        byte[] recordBuffer = new byte[numBytes];
        ByteBuffer record = ByteBuffer.wrap(recordBuffer);
        record.order(ByteOrder.LITTLE_ENDIAN);
        LongBuffer longRecordBuffer = record.asLongBuffer();
        file.seek(offset);
        file.read(recordBuffer);
        long longVal = longRecordBuffer.get();
        return longVal;
    }

    public static String readUnsignedChar(RandomAccessFile file, int offset,
        int numBytes) throws Exception {
        byte[] recordBuffer = new byte[numBytes];
        file.seek(offset);
        file.read(recordBuffer);
        if (numBytes == 1) {
            return "" + recordBuffer[0];
        }
        StringBuffer sb = new StringBuffer();
        for (byte b : recordBuffer) {
            int a = (int)b & 0xFF;
            char c = (char)a;
            if (c != 0x00) {
                sb.append(c);
            } else {
                break;
            }
        }
        return sb.toString();
    }

    public static byte[] readKey(RandomAccessFile file, int offset,
        int numBytes) throws Exception {
        byte[] recordBuffer = new byte[numBytes];
        file.seek(offset);
        file.read(recordBuffer);
        return recordBuffer;
    }

    public static String readWCharStr(RandomAccessFile file, int offset, int numBytes)
            throws Exception {
        char[] charArr = DecryptionUtil.readWCharArr(file, offset, numBytes);
        String str = new String(charArr);
        String actualStr = str.replaceAll("\0", "");
        return actualStr;
    }

    public static Map<String, String> readWCharMap(RandomAccessFile file, int offset,
        int numBytes) throws Exception {
        char[] charArr = DecryptionUtil.readWCharArr(file, offset, numBytes);
        String str = new String(charArr);
        String[] strArr = str.split("\0");
        Map<String, String> strMap = new HashMap<String, String>();
        for (int i = 0; i < strArr.length; i = i + 2) {
            if (strArr[i] != null && !strArr[i].equals("\0")) {
                String val = "";
                if (i != strArr.length - 1) {
                    val = strArr[i + 1];
                }
                strMap.put(strArr[i], val);
            } else {
                break;
            }
        }
        return strMap;
    }

    public static Map<String, List<String>> readWCharSectionMap(RandomAccessFile file, int offset,
        int numBytes) throws Exception {
        char[] charArr = DecryptionUtil.readWCharArr(file, offset, numBytes);
        Map<String, List<String>> strMap = new HashMap<String, List<String>>();
        String str = new String(charArr);
        StringTokenizer tokenizer = new StringTokenizer(str, "\0");
        while (tokenizer.hasMoreTokens()) {
            String tag = tokenizer.nextToken();
            StringTokenizer tagTokenizer = new StringTokenizer(tag, "=");
            String key = tagTokenizer.nextToken().trim();
            String value = "";
            if (tagTokenizer.hasMoreTokens()) {
                value = tagTokenizer.nextToken().trim();
            }
            if (!strMap.containsKey(key)) {
                List<String> valList = new ArrayList<String>();
                strMap.put(key, valList);
            }
            strMap.get(key).add(value);
        }
        return strMap;
    }

    public static char[] readWCharArr(RandomAccessFile file, int offset, int numBytes)
            throws IOException, NXRTERROR {
        byte[] recordBuffer = new byte[numBytes];
        file.seek(offset);
        file.read(recordBuffer);
        // byte[] dataBytes = removeNullBytes(recordBuffer);
        ByteBuffer record = ByteBuffer.wrap(recordBuffer);
        record.order(ByteOrder.LITTLE_ENDIAN);
        CharBuffer charRecordBuffer = record.asCharBuffer();
        char[] charArr = new char[charRecordBuffer.length()];
        charRecordBuffer.get(charArr);
        return charArr;
    }
}
