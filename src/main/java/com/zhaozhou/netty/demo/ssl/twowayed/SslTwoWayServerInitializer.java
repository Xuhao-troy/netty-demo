package com.zhaozhou.netty.demo.ssl.twowayed;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslContext;

public class SslTwoWayServerInitializer extends ChannelInitializer<SocketChannel> {

//    @Override
//    protected void initChannel(SocketChannel sc) throws Exception {
//        ChannelPipeline pipeline = sc.pipeline();
//        //参考链接：https://www.jianshu.com/p/710f70a99cbc
//        //生成服务端keystore的命令（包括Netty服务端公钥、私钥和证书）
//        //keytool -genkey -alias server -keysize 2048 -validity 3650 -keyalg RSA -dname "CN=localhost" -keypass nettyDemo -storepass nettyDemo -keystore serverStore.jks
//
//
//        String keystorePath = "f:/testOpenssl/node2/keystore.jks";
//        String truststorePath = "f:/testOpenssl/node2/truststore.jks";
//
//        SslContext sslCtx = SslTwoWayContextFactory.getServerContextOpenSSL(keystorePath, truststorePath);
//
//        pipeline.addLast("ssl", sslCtx.newHandler(sc.alloc()));
//
//        // On top of the SSL handler, add the text line codec.
//        pipeline.addLast("framer", new LineBasedFrameDecoder(1024, false, false));
//        pipeline.addLast("decoder", new StringDecoder());
//        pipeline.addLast("encoder", new StringEncoder());
//
//        // and then business logic.
//        pipeline.addLast("handler", new SslTwoWayServerHandler());
//    }

    @Override
    protected void initChannel(SocketChannel sc) throws Exception {
        ChannelPipeline pipeline = sc.pipeline();


        SslContext sslCtx = SslTwoWayContextFactory.getServerContextOpenSSL();
        pipeline.addLast("ssl", sslCtx.newHandler(sc.alloc()));


        // On top of the SSL handler, add the text line codec.
        pipeline.addLast("framer", new LineBasedFrameDecoder(1024, false, false));
        pipeline.addLast("decoder", new StringDecoder());
        pipeline.addLast("encoder", new StringEncoder());

        // and then business logic.
        pipeline.addLast("handler", new SslTwoWayServerHandler());
    }
}
