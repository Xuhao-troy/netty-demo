package com.zhaozhou.netty.demo.ssl.twoway;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLEngine;
import java.util.Arrays;

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
        //参考链接：https://www.jianshu.com/p/710f70a99cbc
        //生成服务端keystore的命令（包括Netty服务端公钥、私钥和证书）
        //keytool -genkey -alias server -keysize 2048 -validity 3650 -keyalg RSA -dname "CN=localhost" -keypass nettyDemo -storepass nettyDemo -keystore serverStore.jks

        String keystorePath = "f:/testOpenssl/node1-ec/keystore.jks";
        String truststorePath = "f:/testOpenssl/node1-ec/truststore.jks";
//        String keystorePath = "f:/testOpenssl/node3-ed/keystore.jks";
//        String truststorePath = "f:/testOpenssl/node3-ed/truststore.jks";

        SSLEngine engine = SslTwoWayContextFactory.getServerContext(keystorePath, truststorePath).createSSLEngine();
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
