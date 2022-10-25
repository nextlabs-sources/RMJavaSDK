package com.nextlabs.nxl.pojos;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.RandomAccessFile;

public class RandomAccessFileWithMeta {

    public RandomAccessFileWithMeta(File file, String mode) throws FileNotFoundException {
        this.file = file;
        randomAccessFile = new RandomAccessFile(file, mode);
    }

    public RandomAccessFile getRandomAccessFile() {
        return randomAccessFile;
    }

    public void setRandomAccessFile(RandomAccessFile randomAccessFile) {
        this.randomAccessFile = randomAccessFile;
    }

    public File getFile() {
        return file;
    }

    public void setFile(File file) {
        this.file = file;
    }

    private RandomAccessFile randomAccessFile;
    private File file;

}
