package com.zh.sm2;

import org.bouncycastle.asn1.x500.X500Name;  
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;  
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;  
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;  
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;  
import org.bouncycastle.crypto.params.ECPublicKeyParameters;  
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;  
import org.bouncycastle.jce.provider.BouncyCastleProvider;  
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;  
import org.bouncycastle.operator.ContentSigner;  
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;  
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;  
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;  
  
import java.math.BigInteger;  
import java.security.*;  
import java.security.spec.ECGenParameterSpec;  
import java.security.spec.ECPrivateKeySpec;  
import java.security.spec.ECPublicKeySpec;  
import java.util.Date;  
/**
 * pcks10生成类
 * @author Administrator
 *
 */
public class SM2PKCS10CSRGenerator {  
  
    public static void main(String[] args) throws Exception {  
        // 添加Bouncy Castle作为安全提供者  
        Security.addProvider(new BouncyCastleProvider());  
  
        // 生成SM2密钥对  
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");  
        keyPairGenerator.initialize(new ECGenParameterSpec("sm2p256v1"));  
        KeyPair keyPair = keyPairGenerator.generateKeyPair();  
        PublicKey publicKey = keyPair.getPublic();  
        PrivateKey privateKey = keyPair.getPrivate();  
  
        // 创建PKCS10 CSR  
        X500Name subject = new X500Name("CN=Test SM2 CSR, OU=MyOrg, O=MyOrg Inc, L=City, ST=State, C=Country");  
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);  
  
        // 设置签名算法和私钥  
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SM3WITHSM2");  
        ContentSigner signer = csBuilder.build(privateKey);  
  
        // 生成CSR  
        byte[] csr = csrBuilder.build(signer).getEncoded();  
  
        // 输出CSR  
        System.out.println("PKCS#10 CSR (Base64 encoded):");  
        System.out.println(new String(java.util.Base64.getEncoder().encode(csr)));  
    }  
}