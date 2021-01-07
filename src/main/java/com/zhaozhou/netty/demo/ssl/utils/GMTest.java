package com.zhaozhou.netty.demo.ssl.utils;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLException;
import java.io.File;

/**
 * 类GMTest.java的实现描述：
 *
 * @author xuhao create on 2020/10/22 17:21
 */

public class GMTest {
    public static void test() throws SSLException {

        File caRoot = new File("caRoot.cer");
        File serverCertChainFile = new File("serverChain.pem");
        File serverKey = new File("server.key");

        File clientCertChainFile = new File("clientChain.pem");
        File clientKey = new File("client.key");


        SslContext serverSslContext = SslContextBuilder.forServer(serverCertChainFile, serverKey)
                .trustManager(caRoot).build();

        SslContext clientSslContext = SslContextBuilder.forClient()
                .keyManager(clientCertChainFile, clientKey)
                .trustManager(caRoot).build();

    }

        public static final String stringToEncrypt="This is a test.";

        public static void main(String[] args) throws Exception{


            System.out.print("Attempting to get a Blowfish key...");

            KeyGenerator keyGenerator=KeyGenerator.getInstance("Blowfish");

            keyGenerator.init(128);

            SecretKey key=keyGenerator.generateKey();

            System.out.println("OK");



            System.out.println("Attempting to get a Cipher and encrypt...");

            Cipher cipher=Cipher.getInstance("Blowfish/ECB/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE,key);



            byte[] cipherText=cipher.doFinal(stringToEncrypt.getBytes("UTF8"));

            System.out.println("OK");



            System.out.println("Test completed successfully.");
    }
}
