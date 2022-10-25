package com.nextlabs.junit.test;

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.exception.NXRTERROR;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;

public class RightsManagerTest {

    static RightsManager manager;

    @BeforeClass
    public static void setup() throws NXRTERROR, IOException {
        manager = new RightsManager(new File("C:/temp/config.properties"));
        BufferedWriter writer = new BufferedWriter(new FileWriter(new File("C:/temp/hi.txt")));
        writer.write("Hello");
        writer.flush();
        writer.close();
    }

    @AfterClass
    public static void cleanup() {
        manager.cleanup();
        manager = null;
    }

    @Test(expected = NXRTERROR.class)
    public void InvalidSourceFileEncryptionShouldThrowException() throws Exception {
        manager.encrypt("C:/temp/thisFileWouldNotExist.txt", "C:/temp/thisFileWouldNotExist.txt.nxl", null, null, null);
        fail("NXRTERROR not thrown");
    }

    @Test(expected = NXRTERROR.class)
    public void InvalidSourceFileDecryptionShouldThrowException() throws Exception {
        manager.decrypt("C:/temp/thisFileWouldNotExist.txt.nxl", "C:/temp/thisFileWouldNotExist.txt");
        fail("NXRTERROR not thrown");
    }

    @Test(expected = NXRTERROR.class)
    public void SameSourceDestDecryptShouldThrowException() throws Exception {
        manager.decrypt("C:/temp/hi.txt", "C:/temp/hi.txt");
        fail("NXRTERROR not thrown");
    }

    @Test(expected = NXRTERROR.class)
    public void SameSourceDestDecryptNxlShouldThrowException() throws Exception {
        manager.decrypt("C:/temp/hi.txt.nxl", "C:/temp/hi.txt.nxl");
        fail("NXRTERROR not thrown");
    }

    @Test(expected = NXRTERROR.class)
    public void SameSourceDestEncryptShouldThrowException() throws Exception {
        manager.encrypt("C:/temp/hi.txt", "C:/temp/hi.txt", null, null, null);
        fail("NXRTERROR not thrown");
    }

    @Test(expected = NXRTERROR.class)
    public void SameSourceDestEncryptNxlEncryptShouldThrowException() throws Exception {
        manager.encrypt("C:/temp/hi.txt.nxl", "C:/temp/hi.txt.nxl", null, null, null);
        fail("NXRTERROR not thrown");
    }

    @Test(expected = NXRTERROR.class)
    public void NotNXLEncryptedShouldThrowException() throws Exception {
        manager.encrypt("C:/temp/hi.txt", "C:/temp/hi.txt", null, null, null);
        fail("NXRTERROR not thrown");
    }

    @Test(expected = NXRTERROR.class)
    public void DoubleEncryptionShouldThrowException() throws Exception {
        manager.encrypt("C:/temp/hi.txt.nxl", "C:/temp/hi.txt.nxl", null, null, null);
        fail("NXRTERROR not thrown");
    }

    @Test(expected = NXRTERROR.class)
    public void EmptySourceEncryptShouldThrowException() throws Exception {
        manager.encrypt("", "C:/temp/hi.txt.nxl", null, null, null);
        fail("NXRTERROR not thrown");
    }

    @Test(expected = NXRTERROR.class)
    public void EmptySourceDecryptShouldThrowException() throws Exception {
        manager.decrypt("C:/temp/hi.txt.nxl", "C:/temp/hi.txt.nxl");
        fail("NXRTERROR not thrown");
    }

    @Test(expected = FileNotFoundException.class)
    public void NoWritePermissionShouldThrowException() throws Exception {
        manager.encrypt("C:/temp/hi.txt", "C:/temp/new/hi.txt.nxl", null, null, null);
        fail("NXRTERROR not thrown");
    }

    @Test
    public void ValidWritePermission() throws Exception {
        File file = new File("C:/temp/hi.txt.nxl");
        file.delete();
        manager.encrypt("C:/temp/hi.txt", "C:/temp/hi.txt.nxl", null, null, null);
        File encryptedFile = new File("C:/temp/hi.temp/hi.txt.nxl");
        assert (encryptedFile.exists());
    }

    @Test
    public void LongestSourcePath() throws Exception {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < 150; i++) {
            buffer.append("a");
        }
        buffer.append(".txt");
        try {
            manager.encrypt("C:/temp/hi.txt", "C:/temp/" + buffer.toString() + ".nxl", null, null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
        File encryptedFile = new File("C:/temp/" + buffer.toString() + ".nxl");
        assert (encryptedFile.exists());
    }

    @Test(expected = NXRTERROR.class)
    public void InvalidSourcePath() throws Exception {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < 8000; i++) {
            buffer.append((i % 26) + 65);
        }
        buffer.append(".txt");
        manager.encrypt("C:/temp/hi.txt", buffer.toString(), null, null, null);
        File encryptedFile = new File("C:/temp/hi.temp/hi.txt.nxl");
        assert (encryptedFile.exists());
    }
}
