package com.zhaozhou.netty.demo.ssl.onewayGM;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/**
 * 类MyTrustAllManager.java的实现描述：
 *
 * @author xuhao create on 2020/10/27 13:50
 */

public class MyTrustAllManager implements X509TrustManager {
    private X509Certificate[] issuers;

    public MyTrustAllManager()
    {
        this.issuers = new X509Certificate[0];
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return issuers ;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
    {}

    public void checkServerTrusted(X509Certificate[] chain, String authType)
    {}
}
