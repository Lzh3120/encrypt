package com.util;

import org.bouncycastle.util.encoders.Hex;

public class HexUtil {
	
	//byte数组转base64
	public static String byteToHex(byte[] bytes){
		return new String(Hex.encode(bytes));
	}
	//base64转byte数组
	public static byte[] hexToByte(String hex) {
		return Hex.decode(hex);
	}
}
