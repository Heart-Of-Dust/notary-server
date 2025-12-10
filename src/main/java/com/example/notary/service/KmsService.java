package com.example.notary.service;
import org.springframework.stereotype.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.SecureRandom;

@Component
public class KmsService {
    private final SecretKey master;
    public KmsService() { master = new SecretKeySpec(new byte[32], "AES"); }
    public byte[] encrypt(byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        c.init(Cipher.ENCRYPT_MODE, master, spec);
        byte[] cipher = c.doFinal(plain);
        byte[] out = new byte[iv.length + cipher.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(cipher, 0, out, iv.length, cipher.length);
        return out;
    }
    public byte[] decrypt(byte[] ivCipher) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = java.util.Arrays.copyOfRange(ivCipher, 0, 12);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        c.init(Cipher.DECRYPT_MODE, master, spec);
        return c.doFinal(ivCipher, 12, ivCipher.length - 12);
    }
}