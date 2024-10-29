package br.com.cadastroit.services.crypt;

import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.Setter;

@Setter
public class CryptBean {

    private PasswordEncoder passwordEncoder;

    public boolean validCryptKey(String key, String hash){
        return passwordEncoder.matches(key, hash);
    }
}
