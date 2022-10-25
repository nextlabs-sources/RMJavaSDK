package com.nextlabs.nxl.test;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class WriteByteTest {

    public static void main(String[] args) throws Exception {
        File file = new File("C:/temp/testFile.txt");
        RandomAccessFile randomFile = new RandomAccessFile(file, "rw");
        String signature = "NXLFTM!\0";
        writeString(randomFile, signature, 0);
        writeShort(randomFile, (short)1, 8);
        writeInt(randomFile, 4096, 10);
        randomFile.close();
    }

    public static void writeString(RandomAccessFile file, String data, long offset)
            throws Exception {
        file.seek(offset);
        file.writeBytes(data);
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
        file.write(buffer.array());
    }

    public static void writeLong(RandomAccessFile file, int data, long offset)
            throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(data);
        file.seek(offset);
        file.write(buffer.array());
    }
}
