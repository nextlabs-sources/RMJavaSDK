package com.nextlabs.nxl.test;

import com.nextlabs.nxl.exception.NXRTERROR;
import com.nextlabs.nxl.util.DecryptionUtil;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

public class TagReader {

    public static void main(String[] args) throws IOException, NXRTERROR {
        String inputFilePath = "C:\\Users\\psheoran\\Desktop\\Ruby\\localRuby\\test.pptx.nxl";
        File inputFile = new File(inputFilePath);
        RandomAccessFile file = new RandomAccessFile(inputFile, "r");
        char[] charArr = DecryptionUtil.readWCharArr(file, 8192, 4096);
        Map<String, String> strMap = new HashMap<String, String>();
        String str = new String(charArr);
        String[] strArr = str.split("\0");
        StringTokenizer tokenizer = new StringTokenizer(str, "\0");
        while (tokenizer.hasMoreTokens()) {
            String tag = tokenizer.nextToken();
            StringTokenizer tagTokenizer = new StringTokenizer(tag, "=");
            //			if(tagTokenizer.countTokens()!=2){
            //				throw new NXRTERROR("Invalid tag format");
            //			}
            String key = tagTokenizer.nextToken().trim();
            String value = "";
            if (tagTokenizer.hasMoreTokens()) {
                value = tagTokenizer.nextToken().trim();
            }
            strMap.put(key, value);
        }
        //return strMap;
    }
}
