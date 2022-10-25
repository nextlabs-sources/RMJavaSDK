package com.nextlabs.nxl.util;

import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.io.IOUtils;

public class HttpRequestUtil {

    static {
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
                new javax.net.ssl.HostnameVerifier() {

                    public boolean verify(String hostname,
                        javax.net.ssl.SSLSession sslSession) {
                        return true;
                    }
                });
    }

    public static String sendPostRequest(String urlToPost, byte[] input, Map<String, String> headers) throws Exception {
        URL url = new URL(urlToPost);
        HttpsURLConnection connection = (HttpsURLConnection)url.openConnection();
        connection.setRequestProperty("Content-Type", "application/xml");
        connection.setRequestProperty("Content-Length", Integer.toString(input.length));
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        Iterator<Entry<String, String>> it = headers.entrySet().iterator();
        while (it.hasNext()) {
            Entry entry = it.next();
            connection.setRequestProperty(entry.getKey().toString(), entry.getValue().toString());
        }

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        TrustManager tm = new X509TrustManager() {

            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        sslContext.init(null, new TrustManager[] { tm }, null);
        connection.setSSLSocketFactory(sslContext.getSocketFactory());

        DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
        wr.write(input);
        InputStream xml = connection.getInputStream();
        StringWriter writer = new StringWriter();
        IOUtils.copy(xml, writer);
        String serviceResponse = writer.toString();
        return serviceResponse;
    }
}
