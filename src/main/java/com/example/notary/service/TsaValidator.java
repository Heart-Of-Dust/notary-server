package com.example.notary.service;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.*;
import java.security.cert.*;
import java.util.*;

@Component
public class TsaValidator {
    public record TsaInfo(java.time.Instant time, byte[] messageImprint) {}
    public TsaInfo validateAndExtract(byte[] der) throws Exception {
        TimeStampToken token = new TimeStampToken(new CMSSignedData(der));
        SignerInformation signer = token.getSignerInfos().getSigners().iterator().next();
        Store<X509CertificateHolder> store = token.getCertificates();
        Collection<X509CertificateHolder> col = store.getMatches(signer.getSID());
        if (col.isEmpty()) throw new IllegalArgumentException("no signer cert");
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(col.iterator().next());
        // 这里只做了签名验证，未做完整证书链，请按需要补全
        signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert));
        TimeStampTokenInfo info = token.getTimeStampInfo();
        return new TsaInfo(info.getGenTime().toInstant(), info.getMessageImprintDigest());
    }
}