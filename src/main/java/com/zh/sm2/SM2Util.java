package com.zh.sm2;

import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import com.util.Base64Util;
/**
 * 公私钥工具类
 * @author Administrator
 *
 */
public class SM2Util {
	
	public static void main(String[] args) throws Exception {
		KeyPair keyPair = generateKey();
		
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		System.out.println("生成公私钥");
		System.out.println("Base64公钥：" + Base64Util.byteToBase64(publicKey.getEncoded()));
		System.out.println("Base64私钥：" + Base64Util.byteToBase64(privateKey.getEncoded()));
		
		//读取公私钥
		System.out.println();
		System.out.println("读取公私钥");
		PublicKey readPublicKey = readPublicKey(publicKey.getEncoded());
		PrivateKey readPrivateKey = readPrivateKey(privateKey.getEncoded());
		System.out.println("Base64读取公钥：" + Base64Util.byteToBase64(readPublicKey.getEncoded()));
		System.out.println("Base64读取私钥：" + Base64Util.byteToBase64(readPrivateKey.getEncoded()));
		
		String data = "我是一真正的人!";
		//加密解密
		System.out.println();
		System.out.println("加密解密");
		System.out.println("原文："+data);
		byte[] ciperData = encrypt(publicKey, data.getBytes());
		System.out.println("Base64密文：" + Base64Util.byteToBase64(ciperData));
		byte[] dataBytes = decrypt(privateKey, ciperData);
		System.out.println("解密后数据："+ new String(dataBytes));
		
		//签名验签
		System.out.println("");
		System.out.println("签名验签");
		System.out.println("原文："+data);
		byte[] sign = sign(privateKey, data.getBytes());
		System.out.println("Base64签名值：" + Base64Util.byteToBase64(sign));
		Boolean verify = verify(publicKey, data.getBytes(), sign);
		System.out.println("验签结果：" + verify);
		
		System.out.println("");
		System.out.println("生成PEM格式公私钥");
		String publicKeyPem = getPublicKeyPem(publicKey);
		System.out.println(publicKeyPem);
		String privateKeyPem = getPrivateKeyPem(privateKey);
		System.out.println(privateKeyPem);
		
		
	}
	
	//生成公私钥对
	public static KeyPair generateKey() throws Exception{
		// 添加 BouncyCastle 兼容包
		Security.addProvider(new BouncyCastleProvider());
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
		
		keyPairGenerator.initialize(new ECGenParameterSpec("sm2p256v1"), new SecureRandom());
		// 生成密钥对
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	
	//读取公钥
	public static PublicKey readPublicKey(byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        // 生成 Java 公私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
	}

	//读取私钥
	public static PrivateKey readPrivateKey(byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        // 生成 Java 公私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
	}
	
	//公钥加密
	public static byte[] encrypt(PublicKey publicKey, byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("SM2", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] ciperData = cipher.doFinal(data);
		return ciperData;
	}
	
	//私钥解密
	public static byte[] decrypt(PrivateKey privateKey, byte[] cipherDate) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("SM2", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] data = cipher.doFinal(cipherDate);
		return data;
	}
	
	//私钥签名
	public static byte[] sign(PrivateKey privateKey, byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SM3withSM2", "BC");
		signature.initSign(privateKey);
		signature.update(data);
		byte[] sign = signature.sign();
		return sign;
	}
	
	//公钥验签
	public static Boolean verify(PublicKey publicKey, byte[] data, byte[] sign) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SM3withSM2", "BC");
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(sign);
	}
	//生成公钥PEM
	private static String getPublicKeyPem(PublicKey publicKey) {
		StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        JcaPEMWriter pemWriter = new JcaPEMWriter(printWriter);
        try {
            pemWriter.writeObject(publicKey);
            pemWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                pemWriter.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return stringWriter.toString();
    }
	
	
	//生成私钥PEM
    private static String getPrivateKeyPem(PrivateKey privateKey) {
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        JcaPEMWriter pemWriter = new JcaPEMWriter(printWriter);

        try {
            pemWriter.writeObject(privateKey);
            pemWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                pemWriter.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return stringWriter.toString();
    }
	
}
