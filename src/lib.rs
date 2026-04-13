/*!
# vastdisk-crypto

Public crypto primitives for VASTDISK — AES-256-GCM encryption/decryption,
BLAKE3 hashing, and Ed25519 signature verification.

Licensed under AGPLv3. See LICENSE for details.
*/

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

// ─── Constants ────────────────────────────────────────────────────────────────

/// AES-256-GCM nonce length (12 bytes).
pub const IV_LENGTH: usize = 12;

/// Chunk size used for streaming encryption (1 MB).
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Length prefix size (4 bytes, big-endian u32).
pub const LENGTH_PREFIX: usize = 4;

// ─── Types ────────────────────────────────────────────────────────────────────

/// Deletion payload signed by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionPayload {
    pub file_id: String,
    pub file_hash: String,
    pub deleted_at: String,
    pub deletion_reason: String,
}

/// Result of encrypting data.
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub key_b64: String,
}

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────

/// Encrypt a byte slice with AES-256-GCM, chunked at CHUNK_SIZE.
///
/// Wire format per chunk: `[4-byte BE length][12-byte IV][encrypted data]`
pub fn encrypt(data: &[u8]) -> EncryptResult {
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let key_b64 = B64.encode(key.as_slice());

    let mut out = Vec::new();

    for chunk in data.chunks(CHUNK_SIZE) {
        let nonce_bytes = &rand::random::<[u8; IV_LENGTH]>();
        let nonce = Nonce::from_slice(nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, chunk)
            .expect("AES-256-GCM encryption failed");

        let chunk_len = (IV_LENGTH + ciphertext.len()) as u32;
        out.extend_from_slice(&chunk_len.to_be_bytes());
        out.extend_from_slice(nonce_bytes);
        out.extend_from_slice(&ciphertext);
    }

    // Handle remaining bytes < CHUNK_SIZE (already covered by chunks iterator)

    EncryptResult {
        ciphertext: out,
        key_b64,
    }
}

/// Decrypt a ciphertext blob produced by `encrypt()`.
pub fn decrypt(ciphertext: &[u8], key_b64: &str) -> Result<Vec<u8>, &'static str> {
    let key_bytes = B64
        .decode(key_b64)
        .map_err(|_| "invalid base64 key")?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut out = Vec::new();
    let mut offset = 0;

    while offset + LENGTH_PREFIX <= ciphertext.len() {
        let chunk_len = u32::from_be_bytes(
            ciphertext[offset..offset + LENGTH_PREFIX]
                .try_into()
                .map_err(|_| "corrupt length prefix")?,
        ) as usize;
        offset += LENGTH_PREFIX;

        if offset + chunk_len > ciphertext.len() {
            return Err("ciphertext truncated");
        }

        let iv = &ciphertext[offset..offset + IV_LENGTH];
        offset += IV_LENGTH;

        let enc_data_len = chunk_len - IV_LENGTH;
        let enc_data = &ciphertext[offset..offset + enc_data_len];
        offset += enc_data_len;

        let nonce = Nonce::from_slice(iv);
        let plaintext = cipher
            .decrypt(nonce, enc_data)
            .map_err(|_| "decryption failed (wrong key or corrupt data)")?;
        out.extend_from_slice(&plaintext);
    }

    Ok(out)
}

// ─── BLAKE3 ──────────────────────────────────────────────────────────────────

/// Hash data with BLAKE3 and return the hex-encoded digest.
pub fn hash_blake3(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

// ─── Ed25519 Verification ────────────────────────────────────────────────────

/// Verify an Ed25519 deletion proof signature.
///
/// Returns `true` if the signature is valid for the given payload, signature
/// (base64), and public key (base64).
pub fn verify_deletion_proof(
    payload: &DeletionPayload,
    signature_b64: &str,
    public_key_b64: &str,
) -> bool {
    let payload_json = match serde_json::to_string(payload) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let sig_bytes = match B64.decode(signature_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let pk_bytes = match B64.decode(public_key_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(
        pk_bytes.as_slice().try_into().unwrap_or(&[0u8; 32]),
    ) {
        Ok(k) => k,
        Err(_) => return false,
    };

    verifying_key
        .verify(payload_json.as_bytes(), &sig)
        .is_ok()
}

// ─── WASM bindings (optional) ────────────────────────────────────────────────

#[cfg(feature = "wasm")]
mod wasm {
    use wasm_bindgen::prelude::*;

    use crate::DeletionPayload;

    #[wasm_bindgen]
    pub fn wasm_hash_blake3(data: &[u8]) -> String {
        crate::hash_blake3(data)
    }

    #[wasm_bindgen]
    pub fn wasm_verify_deletion_proof(
        payload_json: &str,
        signature_b64: &str,
        public_key_b64: &str,
    ) -> bool {
        let payload: DeletionPayload = match serde_json::from_str(payload_json) {
            Ok(p) => p,
            Err(_) => return false,
        };
        crate::verify_deletion_proof(&payload, signature_b64, public_key_b64)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        use ed25519_dalek::Signer;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

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
        use ed25519_dalek::Signer;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

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
}
