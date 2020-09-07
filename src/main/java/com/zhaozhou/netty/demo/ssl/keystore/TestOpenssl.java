package com.zhaozhou.netty.demo.ssl.keystore;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.DefaultTlsServer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * 类TestOpenssl.java的实现描述：
 *
 * @author xuhao create on 2020/8/28 15:25
 */

public class TestOpenssl {

    public static void testOpensslInNetty() throws NoSuchAlgorithmException {
//        System.out.println(OpenSsl.isAvailable());
////        OpenSsl openSsl=new OpenSsl();
////        Set<String> cipherSuites = OpenSsl.availableJavaCipherSuites();
//        Set<String> cipherSuites = OpenSsl.availableOpenSslCipherSuites();
//        for (String cs : cipherSuites) {
//            System.out.println(cs);
//        }
        BouncyCastleProvider prov = new BouncyCastleProvider();
        Security.addProvider(prov);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ed25519");
        KeyPair kp = kpg.generateKeyPair();
    }


    public static void main(String[] args) {
        try {
            testOpensslInNetty();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
