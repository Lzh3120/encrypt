package com.rsa;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.util.Base64Util;

public class RSAUtil {

	public static void main(String[] args) throws Exception {
		// 生成RSA公私钥对
		KeyPair keyPair = generateRSAKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		System.out.println("生成公私钥");
		System.out.println("Hex公钥：" + Hex.toHexString(publicKey.getEncoded()));
		System.out.println("Hex私钥：" + Hex.toHexString(privateKey.getEncoded()));

		System.out.println("生成公私钥");
		System.out.println("Base64公钥：" + Base64Util.byteToBase64(publicKey.getEncoded()));
		System.out.println("Base64私钥：" + Base64Util.byteToBase64(privateKey.getEncoded()));

		// 读取公私钥
		System.out.println();
		System.out.println("读取公私钥");
		PublicKey readPublicKey = readPublicKey(publicKey.getEncoded());
		PrivateKey readPrivateKey = readPrivateKey(privateKey.getEncoded());
		System.out.println("Base64读取公钥：" + Base64Util.byteToBase64(readPublicKey.getEncoded()));
		System.out.println("Base64读取私钥：" + Base64Util.byteToBase64(readPrivateKey.getEncoded()));

		String data = "我是一真正的人!";
		// 加密解密
		System.out.println();
		System.out.println("加密解密");
		System.out.println("原文：" + data);
		byte[] ciperData = encrypt(publicKey, data.getBytes());
		System.out.println("Base64密文：" + Base64Util.byteToBase64(ciperData));
		byte[] dataBytes = decrypt(privateKey, ciperData);
		System.out.println("解密后数据：" + new String(dataBytes));

		// 签名验签
		System.out.println("");
		System.out.println("签名验签");
		System.out.println("原文：" + data);
		byte[] sign = sign(privateKey, data.getBytes());
		System.out.println("Base64签名值：" + Base64Util.byteToBase64(sign));
		Boolean verify = verify(publicKey, data.getBytes(), sign);
		System.out.println("验签结果：" + verify);

		System.out.println();
		writePublicKeyPem(readPublicKey, "pubKey.pem");
		PublicKey readPublicKeyPem = readPublicKeyPem2("pubKey.pem");
		System.out.println("pem读取公钥：" + Base64Util.byteToBase64(readPublicKeyPem.getEncoded()));
		
		writeECPrivateKeyPem(readPrivateKey, "privKey.pem");
		PrivateKey readPrivateKeyPem = readECPrivateKeyPem("privKey.pem");
		System.out.println("pem读取私钥：" + Base64Util.byteToBase64(readPrivateKeyPem.getEncoded()));
	}

	public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048, new SecureRandom()); // 使用2048位密钥长度
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	public static byte[] encrypt(PublicKey publicKey, byte[] plaintext) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] ciphertext = cipher.doFinal(plaintext);
		return ciphertext;
	}

	public static byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] plaintext = cipher.doFinal(ciphertext);
		return plaintext;
	}

	public static PublicKey readPublicKey(byte[] publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		// 私钥
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
		return keyFactory.generatePublic(keySpec);

	}

	public static PrivateKey readPrivateKey(byte[] privateKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		// 私钥
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey);
		return keyFactory.generatePrivate(privateKeySpec);
	}

	// 私钥签名
	public static byte[] sign(PrivateKey privateKey, byte[] data)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(data);
		byte[] sign = signature.sign();
		return sign;
	}

	// 公钥验签
	public static Boolean verify(PublicKey publicKey, byte[] data, byte[] sign)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(sign);
	}

	// 生成公钥PEM
	public static void writePublicKeyPem(PublicKey publicKey, String path) throws IOException {
		File file = new File(path);
		try(FileWriter writerPub = new FileWriter(file);
				JcaPEMWriter pemWriterPub = new JcaPEMWriter(writerPub);){
			pemWriterPub.writeObject(
					SubjectPublicKeyInfo.getInstance((ASN1Sequence) ASN1Primitive.fromByteArray(publicKey.getEncoded())));
		}
	}

	// 生成私钥PEM
	public static void writePrivateKeyPem(PrivateKey privateKey, String path) throws IOException {
		File file = new File(path);
		try(FileWriter writerPriv = new FileWriter(file);
				JcaPEMWriter pemWriterPriv = new JcaPEMWriter(writerPriv);){
			PKCS8Generator pkcs8Generator = new JcaPKCS8Generator(privateKey, null);  
			PemObject generate = pkcs8Generator.generate();
			pemWriterPriv.writeObject(generate);
		}
	}
	
	// 生成私钥PEM
	public static void writeECPrivateKeyPem(PrivateKey privateKey, String path) throws IOException {
		File file = new File(path);
		PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(file))) {
			pemWriter.writeObject(privateKeyInfo);
		}
	}

	//读取公钥PEM
	public static PublicKey readPublicKeyPem(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(path);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		try(FileReader keyReader = new FileReader(file);
			PemReader pemReader = new PemReader(keyReader)){
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(content);
			return keyFactory.generatePublic(keySpec);
		}
	}
	//读取公钥PEM
	//https://blog.csdn.net/sonadorje/article/details/118693195
	public static PublicKey readPublicKeyPem2(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(path);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		try(FileReader keyReader = new FileReader(file)){
			PEMParser pemParser = new PEMParser(keyReader);
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
			return converter.getPublicKey(publicKeyInfo);
		}
	}

	//读取私钥PEM
	public static PrivateKey readPrivateKeyPem(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(path);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		try(FileReader keyReader = new FileReader(file);
			PemReader pemReader = new PemReader(keyReader)){
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			System.out.println(content.length);
			System.out.println(Base64Util.byteToBase64(content));
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
			return keyFactory.generatePrivate(privateKeySpec);
		}
	}
	
	//读取私钥PEM
	public static PrivateKey readPrivateKeyPem2(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(path);
		try(FileReader keyReader = new FileReader(file)){
			PEMParser pemParser = new PEMParser(keyReader);
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
			return converter.getPrivateKey(privateKeyInfo);
		}
	}
	
	// 读取私钥PEM
	public static PrivateKey readECPrivateKeyPem(String path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(path);
		try(FileReader keyReader = new FileReader(file);
			PEMParser pemParser = new PEMParser(keyReader);){
			// 读取私钥文件
		    Object parsed = pemParser.readObject();
		    KeyPair pair = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair)parsed);
	        // 打印私钥
	        return pair.getPrivate();
		}
	}
}
