use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::constants::CHUNK_SIZE;
use crate::types::{DecryptOptions, DeletionPayload};
use crate::encryption::{decrypt, decrypt_with_opts, encrypt};
use crate::hash::hash_blake3;
use crate::verification::{verify_deletion_proof, verify_deletion_proof_json};

#[test]
fn roundtrip_encrypt_decrypt() {
    let data = b"hello vastdisk - this is a test payload";
    let result = encrypt(data).unwrap();
    let decrypted = decrypt(&result.ciphertext, &result.key_b64).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn roundtrip_large_data() {
    let data = vec![0x42u8; 3 * CHUNK_SIZE]; // 3 MB
    let result = encrypt(&data).unwrap();
    let decrypted = decrypt(&result.ciphertext, &result.key_b64).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn blake3_hash_deterministic() {
    let data = b"test data";
    let h1 = hash_blake3(data);
    let h2 = hash_blake3(data);
    assert_eq!(h1, h2);
    assert!(!h1.is_empty());
}

#[test]
fn verify_deletion_proof_roundtrip() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let payload = DeletionPayload {
        file_id: "test-id".to_string(),
        file_hash: "abc123".to_string(),
        deleted_at: "2025-01-01T00:00:00Z".to_string(),
        deletion_reason: "expired".to_string(),
    };
    let payload_json = serde_json::to_string(&payload).unwrap();
    let signature = signing_key.sign(payload_json.as_bytes());
    let sig_b64 = B64.encode(signature.to_bytes());
    let pk_b64 = B64.encode(signing_key.verifying_key().to_bytes());

    assert!(verify_deletion_proof(&payload, &sig_b64, &pk_b64).is_ok());
    assert!(verify_deletion_proof_json(&payload_json, &sig_b64, &pk_b64).is_ok());
}

#[test]
fn verify_deletion_proof_tampered() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let payload = DeletionPayload {
        file_id: "test-id".to_string(),
        file_hash: "abc123".to_string(),
        deleted_at: "2025-01-01T00:00:00Z".to_string(),
        deletion_reason: "expired".to_string(),
    };
    let payload_json = serde_json::to_string(&payload).unwrap();
    let signature = signing_key.sign(payload_json.as_bytes());
    let sig_b64 = B64.encode(signature.to_bytes());
    let pk_b64 = B64.encode(signing_key.verifying_key().to_bytes());

    let mut tampered = payload.clone();
    tampered.file_hash = "tampered".to_string();
    assert!(verify_deletion_proof(&tampered, &sig_b64, &pk_b64).is_err());
}

#[test]
fn decrypt_rejects_bad_key_len() {
    let data = b"test";
    let result = encrypt(data).unwrap();
    let err = decrypt(&result.ciphertext, "dG9vLX-short").unwrap_err();
    assert!(matches!(err, crate::types::CryptoError::InvalidKey));
}

#[test]
fn decrypt_rejects_malformed_ciphertext_no_panic() {
    // Valid header then invalid chunk length (too small).
    let data = b"test";
    let result = encrypt(data).unwrap();
    let mut ct = result.ciphertext.clone();
    // Truncate to just header + 4-byte length prefix, with length = 0.
    ct.truncate(24 + 4);
    let err = decrypt(&ct, &result.key_b64).unwrap_err();
    assert!(matches!(err, crate::types::CryptoError::InvalidCiphertext));
}

#[test]
fn legacy_v1_decrypt_requires_opt_in() {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    // Construct a legacy v1 ciphertext: [len][iv][ct] repeated, no header, no AAD.
    let mut rng = OsRng;
    let key = Aes256Gcm::generate_key(&mut rng);
    let cipher = Aes256Gcm::new(&key);
    let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_slice());

    let iv = [7u8; crate::constants::IV_LENGTH];
    let nonce = Nonce::from_slice(&iv);
    let enc = cipher.encrypt(nonce, b"hello".as_ref()).unwrap();
    let chunk_len = (crate::constants::IV_LENGTH + enc.len()) as u32;

    let mut ct = Vec::new();
    ct.extend_from_slice(&chunk_len.to_be_bytes());
    ct.extend_from_slice(&iv);
    ct.extend_from_slice(&enc);

    // Default: reject legacy v1
    assert!(decrypt(&ct, &key_b64).is_err());

    // Opt-in: allow legacy v1
    let pt = decrypt_with_opts(&ct, &key_b64, &DecryptOptions { allow_legacy_v1: true }).unwrap();
    assert_eq!(pt, b"hello");
}
