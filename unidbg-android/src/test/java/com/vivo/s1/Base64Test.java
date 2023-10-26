package com.vivo.s1;

public class Base64Test {
	
	public static void main(String[] args) {
		byte[] encode = Base64.encode("asdf".getBytes(), Base64.DEFAULT);
		System.out.println(new String(encode));
		System.out.println(new String(Base64.decode(encode, Base64.DEFAULT)));
	}

}
