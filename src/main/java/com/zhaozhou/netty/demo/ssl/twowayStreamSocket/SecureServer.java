package com.zhaozhou.netty.demo.ssl.twowayStreamSocket;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Security;
import java.util.logging.Logger;

public class SecureServer {

    private Logger logger = Logger.getLogger(this.getClass().getName());

    private SSLServerSocket sslServerSocket;

    private SSLServerSocket createSSLServerSocket() throws Exception {
        String keystorePath = "F:/testOpenssl/gm/node3/keystore.jks";
        String truststorePath = "F:/testOpenssl/gm/node3/truststore.jks";


        SSLContext context = SslTwoWayContextFactory.getServerContext(keystorePath, truststorePath);
        ServerSocketFactory factory = context.getServerSocketFactory();
        InetAddress bindAddr = InetAddress.getByName("127.0.0.1");
        return (SSLServerSocket) factory.createServerSocket(9999, 0, bindAddr);
    }

    private void start() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
        if (sslServerSocket == null) {
            sslServerSocket = createSSLServerSocket();
        }
        while (true) {
            try {
                Socket socket = sslServerSocket.accept();
                InputStream is = socket.getInputStream();
                byte[] bytes = new byte[Short.MAX_VALUE];
                int len = -1;

                while ((len = is.read(bytes)) > 0) {
                    logger.info(new String(bytes, 0, len));
                    if (len < bytes.length) {
                        break;
                    }
                }
                socket.getOutputStream().write("server balabala ... ".getBytes());
                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        new SecureServer().start();
    }


}
