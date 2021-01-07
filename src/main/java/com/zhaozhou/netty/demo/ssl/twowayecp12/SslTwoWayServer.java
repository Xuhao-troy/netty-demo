package com.zhaozhou.netty.demo.ssl.twowayecp12;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import java.security.Security;

public class SslTwoWayServer {

	private static int PORT = 9999;

	public void run(int port) throws InterruptedException{
		EventLoopGroup bossGroup = new NioEventLoopGroup();
		EventLoopGroup workGroup = new NioEventLoopGroup();
		try{
			ServerBootstrap b = new ServerBootstrap();
			b.group(bossGroup, workGroup)
			.channel(NioServerSocketChannel.class)
			.handler(new LoggingHandler(LogLevel.INFO))
			.childHandler(new SslTwoWayServerInitializer());

			ChannelFuture cf = b.bind(port).sync();

			cf.channel().closeFuture().sync();

		}finally{
			bossGroup.shutdownGracefully();
			workGroup.shutdownGracefully();
		}

	}

	public static void main(String[] args) throws InterruptedException {
		Security.addProvider(new BouncyCastleJsseProvider());
		Security.addProvider(new BouncyCastleProvider());
		new SslTwoWayServer().run(PORT);

	}

}
