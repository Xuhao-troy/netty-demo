package com.zhaozhou.netty.demo.ssl.utils;

import org.bc.pqc.jcajce.provider.BouncyCastlePQCProvider;

import org.bc.pqc.jcajce.spec.RainbowParameterSpec;

import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * 类PQCTest.java的实现描述：
 *
 * @author xuhao create on 2020/11/13 14:20
 */

public class PQCTest {

    public static final String ALGORITHM = "Rainbow";

    private static final String algorithmAssertionMsg =
            "Assumed JRE supports Rainbow key pair generation";

    private static final String keySpecAssertionMsg =
            "Assumed correct key spec statically";


    public static KeyPairGenerator getKPG(final Provider provider, final SecureRandom random) {
        try {
            final KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGORITHM, provider);
            AlgorithmParameterSpec specs = new RainbowParameterSpec();
            gen.initialize(specs, random);
            return gen;
        } catch (NoSuchAlgorithmException ex) {
            throw new AssertionError(algorithmAssertionMsg, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new AssertionError(keySpecAssertionMsg, ex);
        }
    }

    public static void main(String[] args) {
        Date date = new Date(); // this object contains the current date value

        SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMdd");
        System.out.println(formatter.format(date));

        while (true){
            System.out.println(new Random().nextInt(2));

        }
    }

    private void testRandom() {
        while (true) {
            List<BigInteger> resList = new ArrayList<>();
            for (int i = 0; i < 10000; i++) {
//                Random r = new SecureRandom();
//                BigInteger randomid = new BigInteger(250, r);

                UUID uuid = UUID.randomUUID();
                BigInteger randomid = new BigInteger(uuid.toString().replaceAll("-", ""), 16);
//                System.out.println(randomid);
                resList.add(randomid);
            }
            HashMap<BigInteger, Integer> resMap = new HashMap<>();

            for (BigInteger res : resList) {
                Integer count = resMap.get(res);
                if (count == null) {
                    count = 1;
                } else {
                    count++;
                    throw new RuntimeException("res:" + res + " count:" + count);
                }
                resMap.put(res, count);
            }
        }
    }

    private void rainbowTest() {
        try {
            Security.addProvider(new BouncyCastlePQCProvider());
            KeyPairGenerator kpg = PQCTest.getKPG(new BouncyCastlePQCProvider(), new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            PublicKey pubKey = keyPair.getPublic();
            PrivateKey privKey = keyPair.getPrivate();

            byte[] messageHash = "hello,world".getBytes();
            Signature signature = Signature.getInstance("SHA256WITHRainbow", BouncyCastlePQCProvider.PROVIDER_NAME);
            signature.initSign(privKey);
            signature.update(messageHash);
            byte[] sig = signature.sign();

            Signature signature2 = Signature.getInstance("SHA256WITHRainbow", BouncyCastlePQCProvider.PROVIDER_NAME);
            signature2.initVerify(pubKey);
            signature2.update(messageHash);
            boolean verifyRes = signature2.verify(sig);

            System.out.println("verifyRes:" + verifyRes);

            byte[] pubKeyBytes = pubKey.getEncoded();
            byte[] privKeyBytes = privKey.getEncoded();
            System.out.println("privKey:" + Hex.toHexString(privKeyBytes));
            System.out.println("pubKey:" + Hex.toHexString(pubKeyBytes));

            KeyFactory kf = KeyFactory.getInstance("Rainbow");
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);

            PublicKey publicKeyKF = kf.generatePublic(pubKeySpec);
            PrivateKey privKeyKF = kf.generatePrivate(privKeySpec);

            System.out.println("privKey compare:" + Objects.equals(privKey, privKeyKF));
            System.out.println("pubKey compare:" + Objects.equals(pubKey, publicKeyKF));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
