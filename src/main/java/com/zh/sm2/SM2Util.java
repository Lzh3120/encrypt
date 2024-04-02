package com.zh.sm2;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.util.Base64Util;

/**
 * 公私钥工具类
 * 
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

	// 生成公私钥对
	public static KeyPair generateKey() throws Exception {
		// 添加 BouncyCastle 兼容包
		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");

		keyPairGenerator.initialize(new ECGenParameterSpec("sm2p256v1"), new SecureRandom());
		// 生成密钥对
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	// 读取公钥
	public static PublicKey readPublicKey(byte[] publicKeyBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		// 生成 Java 公私钥对象
		KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
	}

	// 读取私钥
	public static PrivateKey readPrivateKey(byte[] privateKeyBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		// 生成 Java 公私钥对象
		KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}

	// 公钥加密
	public static byte[] encrypt(PublicKey publicKey, byte[] data)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("SM2", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] ciperData = cipher.doFinal(data);
		return ciperData;
	}

	// 私钥解密
	public static byte[] decrypt(PrivateKey privateKey, byte[] cipherDate)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("SM2", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] data = cipher.doFinal(cipherDate);
		return data;
	}

	// 私钥签名
	public static byte[] sign(PrivateKey privateKey, byte[] data)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SM3withSM2", "BC");
		signature.initSign(privateKey);
		signature.update(data);
		byte[] sign = signature.sign();
		return sign;
	}

	// 公钥验签
	public static Boolean verify(PublicKey publicKey, byte[] data, byte[] sign)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SM3withSM2", "BC");
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(sign);
	}

	// 生成公钥PEM
	public static void writePublicKeyPem(PublicKey publicKey, String path) throws IOException {
		File file = new File(path);
		try (FileWriter writerPub = new FileWriter(file); JcaPEMWriter pemWriterPub = new JcaPEMWriter(writerPub);) {
			pemWriterPub.writeObject(
					SubjectPublicKeyInfo.getInstance((ASN1Sequence) ASN1Primitive.fromByteArray(publicKey.getEncoded())));
		}
	}

	// 生成私钥PEM
	public static void writePrivateKeyPem(PrivateKey privateKey, String path) throws IOException {
		File file = new File(path);

		try (FileWriter writerPriv = new FileWriter(file); JcaPEMWriter pemWriterPriv = new JcaPEMWriter(writerPriv);) {
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

	// 读取公钥PEM
	public static PublicKey readPublicKeyPem(String path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(path);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
		try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(content);
			return keyFactory.generatePublic(keySpec);
		}
	}

	// 读取公钥PEM
	// https://blog.csdn.net/sonadorje/article/details/118693195
	public static PublicKey readPublicKeyPem2(String path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(path);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
		try (FileReader keyReader = new FileReader(file)) {
			PEMParser pemParser = new PEMParser(keyReader);
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
			return converter.getPublicKey(publicKeyInfo);
		}
	}

	// 读取私钥PEM
	public static PrivateKey readPrivateKeyPem(String path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(path);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
		try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			System.out.println(content.length);
			System.out.println(Base64Util.byteToBase64(content));
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
			return keyFactory.generatePrivate(privateKeySpec);
		}
	}

	// 读取私钥PEM
	public static PrivateKey readPrivateKeyPem1(String path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File file = new File(path);
		try (FileReader keyReader = new FileReader(file)) {
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
