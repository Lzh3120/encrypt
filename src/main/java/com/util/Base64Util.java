package com.util;

import java.util.Base64;

public class Base64Util {
	
	//byte数组转base64
	public static String byteToBase64(byte[] bytes){
		return Base64.getEncoder().encodeToString(bytes);
	}
	//base64转byte数组
	public static byte[] Base64ToByte(String base64) {
		return Base64.getDecoder().decode(base64);
	}
}
