package com.example.notary.service;
import com.example.notary.config.Const;
import com.example.notary.dao.*;
import com.example.notary.dto.Dtos.*;
import com.example.notary.util.*;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.json.JSONObject;
import org.springframework.http.*;
import org.springframework.stereotype.*;
import org.springframework.transaction.annotation.*;
import org.springframework.web.server.*;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.*;

@Service
@Transactional
public class NotaryService {
    private final SimpleHSM hsm;
    private final KmsService kms;
    private final VaultRepo repo;
    private final TsaValidator tsaValidator;
    private final DedupService dedup;

    public NotaryService(SimpleHSM hsm, KmsService kms, VaultRepo repo,
                         TsaValidator tsaValidator, DedupService dedup) {
        this.hsm = hsm; this.kms = kms; this.repo = repo;
        this.tsaValidator = tsaValidator; this.dedup = dedup;
    }

    public RegisterResponse register(RegisterRequest req) throws Exception {
        byte[] plain = hsm.decrypt(CryptoUtil.decodeBase64(req.encrypted_payload()));
        JSONObject json = new JSONObject(new String(plain, StandardCharsets.UTF_8));
        String userId = json.getString("user_id");
        byte[] clientSeed = CryptoUtil.decodeBase64(json.getString("client_seed_key"));
        if (repo.existsById(userId)) throw new ResponseStatusException(HttpStatus.CONFLICT, "user exists");
        KeyPair kp = CryptoUtil.genEd25519();
        byte[] privEnc = kms.encrypt(kp.getPrivate().getEncoded());
        byte[] seedEnc = kms.encrypt(clientSeed);
        String fingerprint = CryptoUtil.base64(CryptoUtil.sha256(kp.getPublic().getEncoded()));
        repo.save(new VaultEntity(userId, seedEnc, privEnc, fingerprint, "ACTIVE", Instant.now()));
        byte[] rootSig = hsm.sign((userId + CryptoUtil.base64(kp.getPublic().getEncoded())).getBytes(StandardCharsets.UTF_8));
        byte[] receipt = hsm.sign(CryptoUtil.sha256((userId + CryptoUtil.base64(clientSeed)).getBytes(StandardCharsets.UTF_8)));
        return new RegisterResponse("success",
                CryptoUtil.base64(kp.getPublic().getEncoded()),
                CryptoUtil.base64(rootSig),
                CryptoUtil.base64(receipt));
    }

    public SignResponse sign(SignRequest req) throws Exception {
        VaultEntity ent = repo.findById(req.user_id())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        if (!"ACTIVE".equals(ent.status())) throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "revoked");
        byte[] tsaToken = CryptoUtil.decodeBase64(req.tsa_token_base64());
        TsaValidator.TsaInfo tsa = tsaValidator.validateAndExtract(tsaToken);
        byte[] imprint = CryptoUtil.sha256(
                req.user_id().getBytes(StandardCharsets.UTF_8),
                Hex.decodeHex(req.msg_hash()),
                CryptoUtil.longToBytesBigEndian(req.client_ts_ms()));
        if (!Arrays.equals(imprint, tsa.messageImprint()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "imprint mismatch");
        java.time.Duration d1 = java.time.Duration.between(tsa.time(), Instant.ofEpochMilli(req.client_ts_ms()));
        java.time.Duration d2 = java.time.Duration.between(Instant.now(), tsa.time());
        if (Math.abs(d1.getSeconds()) > Const.TSA_CLIENT_DELTA ||
                Math.abs(d2.getSeconds()) > Const.TSA_SYSTEM_DELTA)
            throw new ResponseStatusException(HttpStatus.CONFLICT, "time check fail");
        if (dedup.exist(req.user_id(), req.msg_hash(), req.client_ts_ms()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "replay");
        byte[] seed = kms.decrypt(ent.hmacSeedEncrypted());
        byte[] expect = CryptoUtil.hmacSha256(seed, Bytes.concat(
                Hex.decodeHex(req.msg_hash()),
                CryptoUtil.longToBytesBigEndian(req.client_ts_ms())));
        if (!Arrays.equals(expect, Hex.decodeHex(req.auth_code())))
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "bad auth");
        byte[] privBytes = kms.decrypt(ent.signingPrivKeyEncrypted());
        PrivateKey priv = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        byte[] sig = CryptoUtil.sign(priv, Bytes.concat(
                Hex.decodeHex(req.msg_hash()),
                CryptoUtil.longToBytesBigEndian(tsa.time().toEpochMilli())));
        return new SignResponse("success", UUID.randomUUID().toString(),
                tsa.time().toEpochMilli(), CryptoUtil.base64(sig));
    }
}