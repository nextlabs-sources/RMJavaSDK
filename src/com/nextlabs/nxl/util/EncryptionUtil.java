package com.nextlabs.nxl.util;

import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptionUtil {

    private static Logger logger = LoggerFactory.getLogger("EncryptionUtil");

    public static void writeString(RandomAccessFile file, String data, long offset)
            throws Exception {
        file.seek(offset);
        file.writeBytes(data);
    }

    public static void writeBytes(RandomAccessFile file, byte[] data, long offset) throws IOException {
        try {
            file.seek(offset);
            file.write(data);
        } catch (Exception e) {
            logger.error("Error occurred while writing bytes", e);
        }
    }

    /**
     * This method writes bytes in {@code data} to {@code out}
     * @param out
     * @param data
     * @throws IOException
     */
    public static void writeBytes(OutputStream out, byte[] data) throws IOException {
        out.write(data);
    }

    /**
     * Writes {@code length} bytes from {@code data} starting at {@code offset} to {@code out}
     * @param out
     * @param data
     * @param offset
     * @param length
     * @throws IOException
     */
    public static void writeBytes(OutputStream out, byte[] data, int offset, int length) throws IOException {
        out.write(data, offset, length);
    }

    public static void writeShort(RandomAccessFile file, short data, long offset)
            throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(2);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort(data);
        file.write(buffer.array());
    }

    public static void writeInt(RandomAccessFile file, int data, long offset)
            throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(data);
        file.seek(offset);
        file.write(buffer.array());
    }

    public static void writeLong(RandomAccessFile file, long data, long offset)
            throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(data);
        file.seek(offset);
        file.write(buffer.array());
    }

    public static void writeWCharArr(RandomAccessFile file, String str, int offset)
            throws IOException {
        char[] charArray = str.toCharArray();
        byte[] charBytes = new byte[charArray.length * 2];
        ByteBuffer buffer = ByteBuffer.wrap(charBytes);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.asCharBuffer().put(charArray);
        writeBytes(file, buffer.array(), offset);
    }
}
