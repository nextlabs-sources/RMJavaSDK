package com.nextlabs.nxl.samples;

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.pojos.PolicyControllerDetails;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class FileEncryptorUsingPC {

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
        HashMap<String, List<String>> tagMap = new HashMap();
        List<String> classification = new ArrayList<String>();
        List<String> securityClearance = new ArrayList<String>();
        classification.add("ITAR");
        classification.add("EAR");
        securityClearance.add("Level 7");
        tagMap.put("Security Clearance", securityClearance);
        tagMap.put("Classification", classification);

        //Encrypt the file. Change the paths to point to actual files
        String inputFilePath = "C:\\temp\\productSpec.doc";
        String outputFilePath = "C:\\temp\\productSpec.doc.nxl";
        System.out.println(manager.isNXL("\\\\amami\\share\\uber.png.nxl"));
        manager.encrypt(inputFilePath, outputFilePath, null, null, tagMap);
        System.out.println("Encryption Finished");
        System.out.println("--------");

        //Remember to call this method only once when all encryption and decryption operations have been completed.
        //Once this method is called, RightsManager object becomes unusable.
        manager.cleanup();
    }
}
