package com.nextlabs.nxl.util;

import java.io.StringWriter;

import javax.xml.bind.JAXB;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XMLUtil {

    private static Logger logger = LoggerFactory.getLogger("XMLUtil");

    public static String toXml(Object xmlObject) {
        try {
            StringWriter sw = new StringWriter();
            JAXB.marshal(xmlObject, sw);
            return sw.toString();
        } catch (Exception e) {
            logger.error(e.getMessage());
            return null;
        }
    }
}
