package com.example.notary.service;
import com.example.notary.util.CryptoUtil;
import org.springframework.stereotype.*;
import java.security.*;
import java.util.Base64;

@Component
public class SimpleHSM {
    private final KeyPair root;
    public SimpleHSM() throws GeneralSecurityException {
        root = CryptoUtil.genEd25519();
    }
    public byte[] sign(byte[] data) throws GeneralSecurityException {
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(root.getPrivate());
        sig.update(data);
        return sig.sign();
    }
    public boolean verify(byte[] data, byte[] s) throws GeneralSecurityException {
        Signature sig = Signature.getInstance("Ed25519");
        sig.initVerify(root.getPublic());
        sig.update(data);
        return sig.verify(s);
    }
    public PublicKey getRootPublic() { return root.getPublic(); }

    // 模拟 RSA 解密（客户端用公证公钥加密，这里用私钥解密）
    public byte[] decrypt(byte[] cipher) throws GeneralSecurityException {
        // 真实场景用 RSA-OAEP，这里为了编译通过直接返回 base64 解码
        return Base64.getDecoder().decode(cipher);
    }
}