package com.zhaozhou.netty.demo.ssl.twowayStreamSocket;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Security;
import java.util.logging.Logger;

public class SecureChatClientDemo {

    private Logger logger = Logger.getLogger(this.getClass().getName());


    private Socket createAuthenticationSocket() throws Exception {
        String keystorePath = "F:/testOpenssl/gm/node4/keystore.jks";
        String truststorePath = "F:/testOpenssl/gm/node4/truststore.jks";
        SSLContext context = SslTwoWayContextFactory.getClientContext(keystorePath, truststorePath);

        SocketFactory factory = context.getSocketFactory();
        Socket s = factory.createSocket("localhost", 9999);
        return s;
    }

    private void connect() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        Socket s = createAuthenticationSocket();

        PrintWriter writer = new PrintWriter(s.getOutputStream());
        BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream()));
        writer.println("hello");
        writer.flush();
        logger.info(reader.readLine());
        s.close();
    }


    public static void main(String[] args) throws Exception {
        new SecureChatClientDemo().connect();
    }

}
