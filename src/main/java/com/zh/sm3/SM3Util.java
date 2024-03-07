package com.zh.sm3;

import org.bouncycastle.crypto.digests.SM3Digest;

import com.util.Base64Util;

public class SM3Util {
	
	public static void main(String[] args) {
        String str = "Hello, world!";
        byte[] data = str.getBytes();
        byte[] hash = sm3(data);
        String hex = sm3Hex(data);

        System.out.println("SM3摘要：" + Base64Util.byteToBase64(hash));
        System.out.println("SM3 Hex摘要：" + hex);
    }
	
	public static byte[] sm3(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    public static String sm3Hex(byte[] data) {
        byte[] hash = sm3(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
