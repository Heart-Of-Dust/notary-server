package com.example.notary.dao;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
import java.time.Instant;

@Table("notary_vault")
public record VaultEntity(
        @Id String userId,
        byte[] hmacSeedEncrypted,
        byte[] signingPrivKeyEncrypted,
        String pubKeyFingerprint,
        String status,
        Instant createdAt) {}