package com.example.notary.util;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.*;
import java.security.*;
import java.util.*;

public final class CryptoUtil {
    private static final SecureRandom RAND = new SecureRandom();
    public static KeyPair genEd25519() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        return kpg.generateKeyPair();
    }
    public static byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }
    public static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }
    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) md.update(p);
            return md.digest();
        } catch (Exception ignore) { return null; }
    }
    public static byte[] longToBytesBigEndian(long v) {
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putLong(v);
        return buf.array();
    }
    public static String base64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    public static byte[] decodeBase64(String s) { return Base64.getDecoder().decode(s); }
}