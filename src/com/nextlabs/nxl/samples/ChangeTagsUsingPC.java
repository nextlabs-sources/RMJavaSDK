package com.nextlabs.nxl.samples;

import com.nextlabs.nxl.crypt.RightsManager;
import com.nextlabs.nxl.pojos.PolicyControllerDetails;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class ChangeTagsUsingPC {

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
        Map<String, List<String>> tagMap = new HashMap();
        List<String> classification = new ArrayList<String>();
        List<String> securityClearance = new ArrayList<String>();
        classification.add("ITAR");
        classification.add("EAR");
        securityClearance.add("Level 14");
        tagMap.put("Security Clearance", securityClearance);
        tagMap.put("Classification", classification);

        String inputFilePath = "C:\\temp\\productSpec.doc.nxl";

        System.out.println("Original tags are: ");
        Map<String, List<String>> originalTags = manager.readTags(inputFilePath);
        printTags(originalTags);
        manager.updateTags(tagMap, inputFilePath);
        System.out.println("Tags changed");
        System.out.println("--------");
        System.out.println("New tags are: ");
        Map<String, List<String>> newTags = manager.readTags(inputFilePath);
        printTags(newTags);
        //Try removing tags
        manager.removeTags(inputFilePath);
        System.out.println("Tags removed");
        System.out.println("--------");
        Map<String, List<String>> removedTags = manager.readTags(inputFilePath);
        printTags(removedTags);
        System.out.println("Printing tags");
        System.out.println();
        //Remember to call this method only once when all encryption and decryption operations have been completed.
        //Once this method is called, RightsManager object becomes unusable.
        manager.cleanup();
    }

    private static void printTags(Map<String, List<String>> tagMap) {
        Iterator<Entry<String, List<String>>> it = tagMap.entrySet().iterator();
        while (it.hasNext()) {
            Entry<String, List<String>> entry = it.next();
            String name = entry.getKey();
            List<String> value = entry.getValue();
            for (String s : value) {
                System.out.println(name + " : " + s);
            }
        }
    }
}
