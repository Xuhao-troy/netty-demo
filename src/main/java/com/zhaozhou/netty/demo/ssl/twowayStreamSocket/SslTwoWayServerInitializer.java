package com.zhaozhou.netty.demo.ssl.twowayStreamSocket;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLEngine;

public class SslTwoWayServerInitializer extends ChannelInitializer<SocketChannel> {


    @Override
    protected void initChannel(SocketChannel sc) throws Exception {
        ChannelPipeline pipeline = sc.pipeline();

        String keystorePath = "F:/testOpenssl/gm/node3/keystore.jks";
        String truststorePath = "F:/testOpenssl/gm/node3/truststore.jks";


        SSLEngine engine = SslTwoWayContextFactory.getServerContext(keystorePath, truststorePath).createSSLEngine();
        String[] cipherSuites=engine.getEnabledCipherSuites();

        engine.setUseClientMode(false);//设置服务端模式
        engine.setNeedClientAuth(true);//需要客户端验证
        pipeline.addLast("ssl", new SslHandler(engine));

//        SslContext sslCtx = SslTwoWayContextFactory.getServerContextOpenSSL(keystorePath, truststorePath);
//        pipeline.addLast("ssl", sslCtx.newHandler(sc.alloc()));


        // On top of the SSL handler, add the text line codec.
        pipeline.addLast("framer", new LineBasedFrameDecoder(1024, false, false));
        pipeline.addLast("decoder", new StringDecoder());
        pipeline.addLast("encoder", new StringEncoder());

        // and then business logic.
        pipeline.addLast("handler", new SslTwoWayServerHandler());
    }
}
