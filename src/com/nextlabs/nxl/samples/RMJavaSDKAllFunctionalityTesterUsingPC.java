package com.nextlabs.nxl.samples;

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.pojos.NXLFileMetaData;
import com.nextlabs.nxl.pojos.PolicyControllerDetails;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

public class RMJavaSDKAllFunctionalityTesterUsingPC {

    public static void main(String[] args) throws Exception {
        //The file passed to this method should have all the properties needed to configure RMJavaSDK.
        //Please read the javadocs to see how to create config file.
        RightsManager manager = new RightsManager(new File("C:\\temp\\config.properties"));

        //---Another way to create an instance of RightsManager. We can programatically put properties in PolicyControllerDetails object----//
        //We are not using this object in this sample
        PolicyControllerDetails policyControllerDetails = new PolicyControllerDetails();
        policyControllerDetails.setKeyStoreName("C:\\temp\\rmskmc-keystore.jks");
        policyControllerDetails.setKeyStorePassword("123next!");
        policyControllerDetails.setPcHostName("seletar.nextlabs.com");
        policyControllerDetails.setTrustStoreName("C:\\temp\\rmskmc-truststore.jks");
        policyControllerDetails.setRmiPortNum(1499);
        policyControllerDetails.setTrustStorePasswd("123next!");
        RightsManager manager2 = new RightsManager(policyControllerDetails);
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

        String inputFilePath = "C:\\temp\\productSpec.doc";
        String outputFilePath = "C:\\temp\\productSpec.doc.nxl";
        //Encrypt the file. Change the paths to point to actual files
        manager.encrypt(inputFilePath, outputFilePath, null, null, map);
        System.out.println("Encryption Finished");
        System.out.println("--------");

        //Read tags from an encrypted file
        inputFilePath = "C:\\temp\\productSpec.doc.nxl";
        NXLFileMetaData readMeta = manager.readMeta(inputFilePath);
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

        //Decrypt the file. Change the paths to point to actual files
        inputFilePath = "C:\\temp\\productSpec.doc.nxl";
        outputFilePath = "C:\\temp\\productSpec.doc";
        manager.decrypt(inputFilePath, outputFilePath);
        System.out.println("Decryption complete");

        //Remember to call this method only once when all encryption and decryption operations have been completed.
        //Once this method is called, RightsManager object becomes unusable.
        manager.cleanup();
    }
}
