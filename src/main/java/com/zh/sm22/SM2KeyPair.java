package com.zh.sm22;

/**
 * @Author: ZamXie
 * @Description:
 * @Date: Create in 16:05 2021/9/24
 * @Version 1.0
 */
public class SM2KeyPair {

    /** 公钥 */
    private  String publicKey;

    /** 私钥 */
    private String privateKey;

    SM2KeyPair(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }
    
}
