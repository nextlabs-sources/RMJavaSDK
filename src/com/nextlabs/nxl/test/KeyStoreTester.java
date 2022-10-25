package com.nextlabs.nxl.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.util.Enumeration;

public class KeyStoreTester {

    public static void main(String[] args) throws Exception {
        //char[] storePass = "password".toCharArray();
        String directoryPath = "C:\\Users\\psheoran\\Desktop\\jks";
        File directory = new File(directoryPath);
        File[] listOfFiles = directory.listFiles();
        String[] storePasswords = { "password", "123next!" };
        String[] entryPasswords = { "password", "123next!" };
        for (File file : listOfFiles) {
            KeyStore store = KeyStore.getInstance("JCEKS", "SunJCE");
            InputStream input = new FileInputStream(file.getAbsoluteFile());
            System.out.println("Reading file " + file.getAbsolutePath());
            for (String storePass : storePasswords) {
                try {
                    store.load(input, storePass.toCharArray());
                    System.out.println("KeyStore loaded");
                    break;
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
            }
            try {
                System.out.println("Store size is: " + store.size());
            } catch (Exception e) {
                System.out.println(e.getMessage());
                continue;
            }
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                System.out.println("Alias is : " + alias);
                for (String entryPass : entryPasswords) {
                    try {
                        Key entry = store.getKey(alias, entryPass.toCharArray());
                        Class c = entry.getClass();
                        System.out.println("Class of the key is : " + c.toString());
                        System.out.println("Algorithm is : " + entry.getAlgorithm());
                        System.out.println("Entry is : " + entry);
                        System.out.println("Entry.toString() is : " + entry.toString());
                        break;
                    } catch (Exception e) {
                        System.out.println(e.getMessage());
                    }
                }
            }
        }
    }
}
