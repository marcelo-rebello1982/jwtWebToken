package br.com.cadastroit.services.config.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class MainTeste {
	
	
	public String[] decodeBasicAuth(String basicAuthHeader) {
	    // Remove o prefixo "Basic "
	    String base64Credentials = basicAuthHeader.substring("Basic ".length()).trim();
	    
	    // Decodifica o Base64
	    byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
	    String credentials = new String(credDecoded, StandardCharsets.UTF_8);
	    
	    // Separa username e password
	    return credentials.split(":", 2);
	}
	
	public static void main(String[] args) {
		
		MainTeste t = new MainTeste();

		// Uso
		String basicAuthHeader = "Basic c3QtYWRtaW4tMjB4eCMxOiQyeSQxMiR2dVNSTUI0VGY4ekx1WG8uR2Z4NVdlTlAwa21ZbFE1ek5TMU8wcklveFIuaDNDeU1Sc3dvaQ==";
		String[] credentials = t.decodeBasicAuth(basicAuthHeader);
		String username = credentials[0];
		String password = credentials[1];
		String pause = "marcelo";
		
		
	}



}
