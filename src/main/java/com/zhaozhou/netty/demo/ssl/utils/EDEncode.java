package com.zhaozhou.netty.demo.ssl.utils;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * 类EncodeTest.java的实现描述：
 *
 * @author xuhao create on 2020/11/24 14:38
 */

public class EDEncode {

    private static final EdDSAParameterSpec ED25519_CURVE
            = new EdDSAParameterSpec(EdDSAParameterSpec.Ed25519);

    private static ECParameterSpec ecSpec;

    static {
        X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
        ecSpec = new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());
    }

    public static KeyPair initEDKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA", "BC");
        gen.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        return keyPair;
    }


    public static byte[] encrypt(byte[] content, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");//写不写 BC都可以，都是会选择BC实现来做
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }

    public static byte[] decrypt(byte[] content, PrivateKey privateKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(content);
    }

    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPair keyPair = EDEncode.initEDKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println("privateKey:" + Hex.toHexString(privateKey.getEncoded()));
            System.out.println("publicKey:" + Hex.toHexString(publicKey.getEncoded()));

            byte[] plainText = "hello,worldasdf".getBytes();
            System.out.println("plainText:" + Hex.toHexString(plainText));

            byte[] encodeText = encrypt(plainText, publicKey);
            System.out.println("encodeText:" + Hex.toHexString(encodeText));

            byte[] decodeText = decrypt(encodeText, privateKey);
            System.out.println("decodeText:" + Hex.toHexString(decodeText));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
