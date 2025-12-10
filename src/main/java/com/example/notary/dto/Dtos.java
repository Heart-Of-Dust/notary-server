package com.example.notary.dto;

public sealed interface Dtos {
    record RegisterRequest(String user_id, String encrypted_payload) implements Dtos {}
    record RegisterResponse(String status, String user_public_key,
                            String root_endorsement, String confirmation_signature) implements Dtos {}
    record SignRequest(String user_id, String msg_hash, String auth_code,
                       Long client_ts_ms, String tsa_token_base64) implements Dtos {}
    record SignResponse(String status, String transaction_id,
                        Long verified_tsa_time, String signature) implements Dtos {}
}