package com.zhaozhou.netty.demo.ssl.twowayGMOrOpenssl;

import cn.gmssl.jce.provider.GMJCE;
import cn.gmssl.jsse.provider.GMJSSE;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.Security;

public class SecureChatClient {
    private static int PORT = 9999;

    public void start(String host, int port) throws Exception {
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group).channel(NioSocketChannel.class)
                    .handler(new SslTwoWayClientInitializer());

            // Start the connection attempt.
            Channel ch = b.connect(host, port).sync().channel();
            // Read commands from the stdin.
            ChannelFuture lastWriteFuture = null;
            BufferedReader in = new BufferedReader(new InputStreamReader(
                    System.in));
            for (; ; ) {
                String line = in.readLine();
                if (line == null) {
                    break;
                }

                // Sends the received line to the server.
                lastWriteFuture = ch.writeAndFlush(line + "\r\n");

                // If user typed the 'bye' command, wait until the server closes
                // the connection.
                if ("bye".equals(line.toLowerCase())) {
                    ch.closeFuture().sync();
                    break;
                }
            }

            // Wait until all messages are flushed before closing the channel.
            if (lastWriteFuture != null) {
                lastWriteFuture.sync();
            }
        } finally {
            group.shutdownGracefully();
        }
    }

    public static void main(String[] args) throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(),1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(),2);
        new SecureChatClient().start("localhost", PORT);

    }

}
