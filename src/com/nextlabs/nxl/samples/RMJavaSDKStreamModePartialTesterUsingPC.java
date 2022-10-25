package com.nextlabs.nxl.samples;

import com.nextlabs.nxl.Constants;

/**
 * @author nnallagatla
 *
 */

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.crypt.StreamDecryptionState;
import com.nextlabs.nxl.pojos.NXLFileMetaData;
import com.nextlabs.nxl.pojos.PolicyControllerDetails;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import org.apache.commons.io.IOUtils;

public class RMJavaSDKStreamModePartialTesterUsingPC {

    public static void main(String[] args) throws Exception {
        //The file passed to this method should have all the properties needed to configure RMJavaSDK.
        //Please read the javadocs to see how to create config file.

        PolicyControllerDetails policyControllerDetails = new PolicyControllerDetails();
        policyControllerDetails.setKeyStoreName("C:\\temp-src\\rmskmc-keystore.jks");
        policyControllerDetails.setKeyStorePassword("123next!");
        policyControllerDetails.setPcHostName("rms-jpc.qapf1.qalab01.nextlabs.com");
        policyControllerDetails.setTrustStoreName("C:\\temp-src\\rmskmc-truststore.jks");
        policyControllerDetails.setRmiPortNum(1499);
        policyControllerDetails.setTrustStorePasswd("123next!");
        RightsManager manager = new RightsManager(policyControllerDetails);
        //---------------------------------------------------------//

        //Create tags to add to encrypted file
        HashMap<String, List<String>> map = new HashMap();
        List<String> classification = new ArrayList<String>();
        List<String> securityClearance = new ArrayList<String>();
        classification.add("ITAR");
        classification.add("EAR");
        securityClearance.add("Level 7");
        map.put("Security Clearance", securityClearance);
        map.put("Classification", classification);

        String inputFilePath = "C:\\temp-src\\test.txt";
        String outputFilePath = "C:\\temp-src\\test.txt.nxl";
        
        long start = args.length == 2 ? Long.parseLong(args[0]) : 0;
        long length = args.length == 2 ? Long.parseLong(args[1]) : 100;
        //Encrypt the file. Change the paths to point to actual files

        File f1 = new File(inputFilePath);
        File f2 = new File(outputFilePath);

        InputStream in = new FileInputStream(f1);
        OutputStream out = new FileOutputStream(f2);

        System.out.println("size of encrypted file will be: " + RightsManager.getStandardEncryptedContentSize(f1.length()));

        try {
            manager.encryptStream(in, out, f1.length(), f1.getName(), null, null, map, null);
        } finally {
            in.close();
            out.close();
        }
        System.out.println("Encryption Finished");

        System.out.println("size of encrypted file is: " + f2.length());

        System.out.println("--------");

        //Decrypt the file. Change the paths to point to actual files
        inputFilePath = "C:\\temp-src\\test.txt.nxl";
        outputFilePath = "C:\\temp-src\\test-new.txt";

        f1 = new File(inputFilePath);
        f2 = new File(outputFilePath);

        in = new FileInputStream(f1);
        out = new FileOutputStream(f2);

        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            IOUtils.copyLarge(in, bos, 0, Constants.STANDARD_NXL_HEADER_SIZE);
            StreamDecryptionState state = manager.buildStreamDecryptionState(bos.toByteArray(), null);
            System.out.println("Original File Size: " + manager.getOriginalContentLength(state));
            manager.decryptPartial(in, out, state, start, length, true);
            NXLFileMetaData readMeta = state.getNXLFileMetaData();
            Iterator<Entry<String, List<String>>> it = readMeta.getTags().entrySet().iterator();
            while (it.hasNext()) {
                Entry<String, List<String>> entry = it.next();
                System.out.println("Key: " + entry.getKey());
                for (int i = 0; i < entry.getValue().size(); i++) {
                    System.out.println("Value: " + entry.getValue().get(i));
                }
                System.out.println("--------");
            }
            System.out.println("Tags read");
            System.out.println("--------");

        } finally {
            in.close();
            out.close();
        }
        System.out.println("Decryption complete");

        //Remember to call this method only once when all encryption and decryption operations have been completed.
        //Once this method is called, RightsManager object becomes unusable.
        manager.cleanup();
    }
}
