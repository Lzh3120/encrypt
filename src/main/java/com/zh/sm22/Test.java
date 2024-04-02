package com.zh.sm22;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.util.encoders.Hex;

public class Test {
	public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
		SM2Util sm2 = new SM2Util();
		SM2KeyPair keyPair = sm2.generateKeyPair();
		String privateKey = keyPair.getPrivateKey();
		String publicKey = keyPair.getPublicKey();
		System.out.println(privateKey);
		System.out.println(publicKey);
		
		String encrypt = sm2.encrypt(Hex.decodeStrict(publicKey), "123978".getBytes());
	
		byte[] decrypt = sm2.decrypt(Hex.decodeStrict(privateKey), Hex.decodeStrict(encrypt));
		System.out.println(new String(decrypt));
	}
}
