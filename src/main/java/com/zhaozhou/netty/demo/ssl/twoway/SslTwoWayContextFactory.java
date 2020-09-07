package com.zhaozhou.netty.demo.ssl.twoway;

import com.zhaozhou.netty.demo.ssl.utils.TlsTestUtils;
import io.netty.handler.ssl.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public final class SslTwoWayContextFactory {

    private static final String PROTOCOL = "TLS";

    private static SSLContext SERVER_CONTEXT;//服务器安全套接字协议

    private static SslContext SERVER_CONTEXT_OPENSSL;//服务器安全套接字协议

    private static SSLContext CLIENT_CONTEXT;//客户端安全套接字协议

    private static SslContext CLIENT_CONTEXT_OPENSSL;//客户端安全套接字协议


    public static SSLContext getServerContext(String pkPath, String caPath) {
        if (SERVER_CONTEXT != null) return SERVER_CONTEXT;
        try {
            char[] keyPass = "keyPassword".toCharArray();

            KeyStore serverKS = loadKSfromKSFile(pkPath, keyPass);
            KeyStore serverTS = loadKSfromKSFile(caPath, keyPass);

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            keyMgrFact.init(serverKS, keyPass);

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            trustMgrFact.init(serverTS);

            SERVER_CONTEXT = SSLContext.getInstance(PROTOCOL, BouncyCastleJsseProvider.PROVIDER_NAME);
            //初始化此上下文
            //参数一：认证的密钥      参数二：对等信任认证  参数三：伪随机数生成器 。 由于单向认证，服务端不用验证客户端，所以第二个参数为null
            SERVER_CONTEXT.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));

        } catch (Exception e) {
            throw new Error("Failed to initialize the server-side SSLContext", e);
        }
        return SERVER_CONTEXT;
    }


    public static SSLContext getClientContext(String pkPath, String caPath) {
        if (CLIENT_CONTEXT != null) return CLIENT_CONTEXT;
        try {
            char[] keyPass = "keyPassword".toCharArray();

            KeyStore clientKS = loadKSfromKSFile(pkPath, keyPass);
            KeyStore clientTS = loadKSfromKSFile(caPath, keyPass);

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            keyMgrFact.init(clientKS, keyPass);

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            trustMgrFact.init(clientTS);

            CLIENT_CONTEXT = SSLContext.getInstance(PROTOCOL, BouncyCastleJsseProvider.PROVIDER_NAME);
            //初始化此上下文
            //参数一：认证的密钥      参数二：对等信任认证  参数三：伪随机数生成器 。 由于单向认证，服务端不用验证客户端，所以第二个参数为null
            CLIENT_CONTEXT.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));

        } catch (Exception e) {
            throw new Error("Failed to initialize the client-side SSLContext", e);
        }
        return CLIENT_CONTEXT;
    }

    private static KeyStore loadKSfromKSFile(String keyStorePath, char[] keyPass) throws Exception {
        InputStream in = null;
        KeyStore ks = KeyStore.getInstance("JKS");
        in = new FileInputStream(keyStorePath);
        ks.load(in, keyPass);
        return ks;
    }


    public static SslContext getClientContextOpenSSL(String pkPath, String caPath) {
        if (CLIENT_CONTEXT_OPENSSL != null) return CLIENT_CONTEXT_OPENSSL;
        InputStream in = null;
        InputStream tIN = null;
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            in = new FileInputStream(pkPath);
            ks.load(in, "123456".toCharArray());
//            OpenSslCachingX509KeyManagerFactory kmf = new OpenSslCachingX509KeyManagerFactory(KeyManagerFactory.getInstance("SunX509"));
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "123456".toCharArray());

            TrustManagerFactory tf = null;
            KeyStore tks = KeyStore.getInstance("JKS");
            tIN = new FileInputStream(caPath);
            tks.load(tIN, "123456".toCharArray());
            tf = TrustManagerFactory.getInstance("SunX509");
            tf.init(tks);
            CLIENT_CONTEXT_OPENSSL = SslContextBuilder.forClient().keyManager(kmf).trustManager(tf).build();
        } catch (Exception e) {
            e.printStackTrace();
            throw new Error("Failed to initialize the client-side SSLContext.");
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                in = null;
            }

            if (tIN != null) {
                try {
                    tIN.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                tIN = null;
            }
        }
        return CLIENT_CONTEXT_OPENSSL;
    }

    public static SslContext getServerContextOpenSSL(String pkPath, String caPath) {
        if (SERVER_CONTEXT_OPENSSL != null) return SERVER_CONTEXT_OPENSSL;
        InputStream in = null;
        InputStream tIN = null;
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            in = new FileInputStream(pkPath);
            ks.load(in, "123456".toCharArray());
//            OpenSslCachingX509KeyManagerFactory kmf = new OpenSslCachingX509KeyManagerFactory(KeyManagerFactory.getInstance("SunX509"));
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "123456".toCharArray());

            TrustManagerFactory tf = null;
            KeyStore tks = KeyStore.getInstance("JKS");
            tIN = new FileInputStream(caPath);
            tks.load(tIN, "123456".toCharArray());
            tf = TrustManagerFactory.getInstance("SunX509");
            tf.init(tks);
            SERVER_CONTEXT_OPENSSL = SslContextBuilder.forServer(kmf).trustManager(tf).clientAuth(ClientAuth.REQUIRE).build();
        } catch (Exception e) {
            e.printStackTrace();
            throw new Error("Failed to initialize the client-side SSLContext.");
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                in = null;
            }

            if (tIN != null) {
                try {
                    tIN.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                tIN = null;
            }
        }
        return SERVER_CONTEXT_OPENSSL;
    }
}
