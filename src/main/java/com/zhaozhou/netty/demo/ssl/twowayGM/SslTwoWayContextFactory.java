package com.zhaozhou.netty.demo.ssl.twowayGM;

import cn.gmssl.jce.provider.GMJCE;
import cn.gmssl.jsse.provider.GMJSSE;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

public final class SslTwoWayContextFactory {

    private static final String PROTOCOL = GMJSSE.GMSSLv11;
//    private static final String PROTOCOL = "SSLv3";

    private static SSLContext SERVER_CONTEXT;//服务器安全套接字协议

    private static SslContext SERVER_CONTEXT_OPENSSL;//服务器安全套接字协议

    private static SSLContext CLIENT_CONTEXT;//客户端安全套接字协议

    private static SslContext CLIENT_CONTEXT_OPENSSL;//客户端安全套接字协议


    public static SSLContext getServerContext(String pkPath, String caPath) {
        if (SERVER_CONTEXT != null) return SERVER_CONTEXT;
        try {
            char[] keyPass = "123456".toCharArray();

            KeyStore serverKS = loadKSfromKSFile(pkPath, keyPass);
            KeyStore serverTS = loadKSfromKSFile(caPath, keyPass);

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");
            keyMgrFact.init(serverKS, keyPass);

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");
            trustMgrFact.init(serverTS);

            SERVER_CONTEXT = SSLContext.getInstance(PROTOCOL, GMJSSE.NAME);
            //初始化此上下文
            //参数一：认证的密钥      参数二：对等信任认证  参数三：伪随机数生成器 。 由于单向认证，服务端不用验证客户端，所以第二个参数为null
            SERVER_CONTEXT.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), new SecureRandom());
        } catch (Exception e) {
            throw new Error("Failed to initialize the server-side SSLContext", e);
        }
        return SERVER_CONTEXT;
    }


    public static SSLContext getClientContext(String pkPath, String caPath) {
        if (CLIENT_CONTEXT != null) return CLIENT_CONTEXT;
        try {
            char[] keyPass = "123456".toCharArray();

            KeyStore clientKS = loadKSfromKSFile(pkPath, keyPass);
            KeyStore clientTS = loadKSfromKSFile(caPath, keyPass);

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");
            keyMgrFact.init(clientKS, keyPass);

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");
            trustMgrFact.init(clientTS);

            CLIENT_CONTEXT = SSLContext.getInstance(PROTOCOL, GMJSSE.NAME);
            //初始化此上下文
            //参数一：认证的密钥      参数二：对等信任认证  参数三：伪随机数生成器 。 由于单向认证，服务端不用验证客户端，所以第二个参数为null
            CLIENT_CONTEXT.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), new SecureRandom());

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


    public static SslContext getClientContextOpenSSL() {
        if (CLIENT_CONTEXT_OPENSSL != null) return CLIENT_CONTEXT_OPENSSL;

        try {
            File caRoot = new File("F:/testOpenssl/gm/node2/ca.crt");
            File clientCertChainFile = new File("F:/testOpenssl/gm/node2/chain2.crt");
            File clientKey = new File("F:/testOpenssl/gm/node2/node2key.pem");

            CLIENT_CONTEXT_OPENSSL = SslContextBuilder.forClient()
                    .keyManager(clientCertChainFile, clientKey)
                    .trustManager(caRoot).build();
        } catch (Exception e) {
            e.printStackTrace();
            throw new Error("Failed to initialize the client-side SSLContext.");
        }
        return CLIENT_CONTEXT_OPENSSL;
    }

    public static SslContext getServerContextOpenSSL() {
        if (SERVER_CONTEXT_OPENSSL != null) return SERVER_CONTEXT_OPENSSL;
        try {
            File caRoot = new File("F:/testOpenssl/gm/node1/ca.crt");
            File serverCertChainFile = new File("F:/testOpenssl/gm/node1/chain1.crt");
            File serverKey = new File("F:/testOpenssl/gm/node1/node1key.pem");
            SERVER_CONTEXT_OPENSSL = SslContextBuilder.forServer(serverCertChainFile, serverKey)
                    .trustManager(caRoot).build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new Error("Failed to initialize the client-side SSLContext.");
        }
        return SERVER_CONTEXT_OPENSSL;
    }


    private static KeyStore loadKSfromP12File(String keyStorePath, char[] keyPass) throws Exception {
        InputStream in = null;
        KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        in = new FileInputStream(keyStorePath);
        ks.load(in, keyPass);

        return ks;
    }


}
