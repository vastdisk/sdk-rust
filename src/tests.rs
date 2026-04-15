use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::constants::CHUNK_SIZE;
use crate::types::DeletionPayload;
use crate::encryption::{decrypt, encrypt};
use crate::hash::hash_blake3;
use crate::verification::verify_deletion_proof;

#[test]
fn roundtrip_encrypt_decrypt() {
    let data = b"hello vastdisk - this is a test payload";
    let result = encrypt(data);
    let decrypted = decrypt(&result.ciphertext, &result.key_b64).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn roundtrip_large_data() {
    let data = vec![0x42u8; 3 * CHUNK_SIZE]; // 3 MB
    let result = encrypt(&data);
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

    assert!(verify_deletion_proof(&payload, &sig_b64, &pk_b64));
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
    assert!(!verify_deletion_proof(&tampered, &sig_b64, &pk_b64));
}
