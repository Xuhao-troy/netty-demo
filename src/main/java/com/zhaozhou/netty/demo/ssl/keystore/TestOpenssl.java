package com.zhaozhou.netty.demo.ssl.keystore;


import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

/**
 * 类TestOpenssl.java的实现描述：
 *
 * @author xuhao create on 2020/8/28 15:25
 */

public class TestOpenssl {

    public static void testOpensslInNetty() throws Exception {
//        System.out.println(OpenSsl.isAvailable());
////        OpenSsl openSsl=new OpenSsl();
////        Set<String> cipherSuites = OpenSsl.availableJavaCipherSuites();
//        Set<String> cipherSuites = OpenSsl.availableOpenSslCipherSuites();
//        for (String cs : cipherSuites) {
//            System.out.println(cs);
//        }
        BouncyCastleProvider prov = new BouncyCastleProvider();
        Security.addProvider(prov);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = kpg.generateKeyPair();

        //加载私钥
        String keyPath = "f:\\testOpenssl\\node4-ed\\node.key";
        PrivateKey privateKey = loadPrivKeyFromFile(keyPath);
        BCEdDSAPrivateKey privKey = (BCEdDSAPrivateKey) privateKey;
        BCEdDSAPublicKey pubKey = (BCEdDSAPublicKey) privKey.getPublicKey();

        Signature signature = Signature.getInstance("Ed25519", "BC");
//签名
        signature.initSign(privKey);
        byte[] msg = Strings.toByteArray("Hello, world!");

        signature.update(msg);

        byte[] sig = signature.sign();
//验签
        signature.initVerify(pubKey);

        signature.update(msg);

        System.out.println(signature.verify(sig));
    }

    private static PrivateKey loadPrivKeyFromFile(String filePath) {
        try {
            FileInputStream fis = new FileInputStream(filePath);
            PemReader pemReader = new PemReader(new InputStreamReader(fis));
            PemObject pemObject = pemReader.readPemObject();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
            KeyFactory factory = KeyFactory.getInstance("ed25519");
            PrivateKey privateKey = factory.generatePrivate(privKeySpec);
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        try {
            testOpensslInNetty();
        } catch (Exception e) {
            e.printStackTrace();
        }

        Ed25519Signer signer = new Ed25519Signer();

    }
}
