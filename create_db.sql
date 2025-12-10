CREATE DATABASE notary;
\c notary
CREATE TABLE notary_vault (
                              user_id  VARCHAR(64) PRIMARY KEY,
                              hmac_seed_encrypted        BYTEA NOT NULL,
                              signing_priv_key_encrypted BYTEA NOT NULL,
                              pub_key_fingerprint        VARCHAR(64) NOT NULL,
                              status                     VARCHAR(20) DEFAULT 'ACTIVE',
                              created_at TIMESTAMPTZ DEFAULT NOW()
);