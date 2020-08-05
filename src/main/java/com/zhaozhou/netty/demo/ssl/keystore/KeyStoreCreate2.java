package com.zhaozhou.netty.demo.ssl.keystore;

import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

/**
 * 类KeyStoreCreate.java的实现描述：
 *
 * @author xuhao create on 2020/8/3 20:03
 */

public class KeyStoreCreate2 {


    public static void main(String[] args) throws GeneralSecurityException, IOException {
        BouncyCastleProvider prov = new BouncyCastleProvider();
        Security.addProvider(prov);

        testSignAndVerify();
        loadFileAndCreateKeyStore();
        loadFileAndCreateTrustStore();
    }

    private static void createKeyStore() throws GeneralSecurityException {
        try {
            String filePath = "f:\\testOpenssl\\new_KeyStore.keystore";
            int keysize = 1024;
            String commonName = "com.baidu.xxx";
            String organizationalUnit = "IT";
            String organization = "baidu";
            String city = "beijing";
            String state = "beijing";
            String country = "beijing";
            long validity = 20000; // 3 years
            String alias = "beijingbaidu";
            char[] keyPassword = "pwd123456".toCharArray();
            KeyStore ks = KeyStore.getInstance("pkcs12");
//            char[] password = "123456".toCharArray();
            ks.load(null, null);

            CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
            X500Name x500Name = new X500Name(commonName, organizationalUnit, organization, city, state, country);
            keypair.generate(keysize);

            PrivateKey privateKey = keypair.getPrivateKey();
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = keypair.getSelfCertificate(x500Name, new Date(), (long) validity * 24 * 60 * 60);

            // store away the key store
            FileOutputStream fos = new FileOutputStream(filePath);
            ks.setKeyEntry(alias, privateKey, keyPassword, chain);
            ks.store(fos, keyPassword);
            fos.close();
            System.out.println("create Success");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void loadFileAndCreateKeyStore() {
        try {

            KeyStore ks = KeyStore.getInstance("JKS");
//            char[] password = "123456".toCharArray();
            ks.load(null, null);
            //加载私钥
            String keyPath = "f:\\testOpenssl\\node2\\node.key";
            PrivateKey privateKey = loadPrivKeyFromFile(keyPath);
            //加载证书链
            String nodeCertPath = "f:\\testOpenssl\\node2\\node.crt";
            Certificate nodeCert=loadCertificateFromFile(nodeCertPath);

            String agencyCertPath = "f:\\testOpenssl\\node2\\agency.crt";
            Certificate agencyCert=loadCertificateFromFile(agencyCertPath);

            String caCertPath = "f:\\testOpenssl\\node2\\ca.crt";
            Certificate caCert=loadCertificateFromFile(caCertPath);

            Certificate[] chain = new X509Certificate[3];
            //证书链组成：node -> agency -> ca
            chain[0]=nodeCert;
            chain[1]=agencyCert;
            chain[2]=caCert;

            // store away the key store

            String filePath = "f:\\testOpenssl\\node2\\keystore.jks";
            String alias = "node2";
            char[] keyPassword = "123456".toCharArray();
            FileOutputStream fos = new FileOutputStream(filePath);
            ks.setKeyEntry(alias, privateKey, keyPassword, chain);
            ks.store(fos, keyPassword);
            fos.close();
            System.out.println("create Success");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void loadFileAndCreateTrustStore() {
        try {

            KeyStore ks = KeyStore.getInstance("JKS");
//            char[] password = "123456".toCharArray();
            ks.load(null, null);
            //加载证书
            String certPath = "f:\\testOpenssl\\node1\\ca.crt";
            Certificate cert= loadCertificateFromFile(certPath);
            // store away the key store

            String filePath = "f:\\testOpenssl\\node1\\truststore.jks";
            String alias = "node1";
            char[] keyPassword = "123456".toCharArray();
            FileOutputStream fos = new FileOutputStream(filePath);
            ks.setCertificateEntry(alias, cert);
            ks.store(fos, keyPassword);
            fos.close();
            System.out.println("create Success");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static PrivateKey loadPrivKeyFromFile(String filePath) {
        try {
            FileInputStream fis = new FileInputStream(filePath);
            PemReader pemReader = new PemReader(new InputStreamReader(fis));
            PemObject pemObject = pemReader.readPemObject();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
            KeyFactory factory = KeyFactory.getInstance("ECDSA");
            PrivateKey privateKey = factory.generatePrivate(privKeySpec);

            BCECPrivateKey privkey = (BCECPrivateKey) privateKey;
            System.out.println("privKey.d:" + privkey.getD());
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static PublicKey loadPubKeyFromFile() {
        try {
            String keyPath = "f:\\testOpenssl\\node1\\node.pubkey";
            FileInputStream fis = new FileInputStream(keyPath);
            PemReader pemReader = new PemReader(new InputStreamReader(fis));
            PemObject pemObject = pemReader.readPemObject();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemObject.getContent());
            KeyFactory factory = KeyFactory.getInstance("ECDSA");
            PublicKey publicKey = factory.generatePublic(keySpec);

            BCECPublicKey pubKey = (BCECPublicKey) publicKey;
            System.out.println("pubkey:" + Arrays.toString(pubKey.getQ().getEncoded(false)));

            return publicKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    private static Certificate loadCertificateFromFile(String filePath) {
        try {
            FileInputStream fis = new FileInputStream(filePath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
            Certificate cert = cf.generateCertificate(fis);
//            PublicKey publicKey = cert.getPublicKey();
//            BCECPublicKey pubKey = (BCECPublicKey) publicKey;
//            System.out.println("pubkey from cert:" + Arrays.toString(pubKey.getQ().getEncoded(false)));
            return cert;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void testSignAndVerify() {
        try {
            BouncyCastleProvider prov = new BouncyCastleProvider();
            Security.addProvider(prov);
            //1. 从文件中读取ECDSA公私钥
            PrivateKey privateKey = loadPrivKeyFromFile( "f:\\testOpenssl\\node1\\node.key");
            PublicKey publicKey = loadPubKeyFromFile();
            //2.签名验签
            //使用ECDSA进行签名和验签
            String text = "This is a message";
            Signature signature = Signature.getInstance("SHA1WithECDSA", prov.getName());
            signature.initSign(privateKey);
            signature.update(text.getBytes());
            byte[] sig = signature.sign();
            //验签
            Signature verifier = Signature.getInstance("SHA1WithECDSA", prov.getName());
            verifier.initVerify(publicKey);
            verifier.update(text.getBytes());
            boolean res = verifier.verify(sig);
            System.out.println("verify result:" + res);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
