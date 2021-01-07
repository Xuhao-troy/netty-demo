package com.zhaozhou.netty.demo.ssl.twowayStreamSocket;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLEngine;

public class SslTwoWayClientInitializer extends ChannelInitializer<SocketChannel> {


//    @Override
//    protected void initChannel(SocketChannel ch) throws Exception {
//        ChannelPipeline pipeline = ch.pipeline();
//
//
//        SslContext sslCtx = SslTwoWayContextFactory.getClientContextOpenSSL();
//        pipeline.addLast("ssl", sslCtx.newHandler(ch.alloc()));
//
//        // On top of the SSL handler, add the text line codec.
//        pipeline.addLast("framer", new LineBasedFrameDecoder(1024, false, false));
//        pipeline.addLast("decoder", new StringDecoder());
//        pipeline.addLast("encoder", new StringEncoder());
//        // and then business logic.
//        pipeline.addLast("handler", new SslTowWayClientHandler());
//    }

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        ChannelPipeline pipeline = ch.pipeline();

        String keystorePath = "F:/testOpenssl/gm/node4/keystore.jks";
        String truststorePath = "F:/testOpenssl/gm/node4/truststore.jks";


        SSLEngine engine = SslTwoWayContextFactory.getClientContext(keystorePath, truststorePath).createSSLEngine();
        String[] cipherSuites=engine.getEnabledCipherSuites();
        engine.setEnabledCipherSuites(cipherSuites);

        engine.setUseClientMode(true);
        pipeline.addLast("ssl", new SslHandler(engine));

        pipeline.addLast("framer", new LineBasedFrameDecoder(1024, false, false));
        pipeline.addLast("decoder", new StringDecoder());
        pipeline.addLast("encoder", new StringEncoder());
        // and then business logic.
        pipeline.addLast("handler", new SslTowWayClientHandler());
    }
}
