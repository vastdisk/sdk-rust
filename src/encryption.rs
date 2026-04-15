use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::constants::{CHUNK_SIZE, IV_LENGTH, LENGTH_PREFIX};
use crate::types::EncryptResult;

/// Encrypt a byte slice with AES-256-GCM, chunked at CHUNK_SIZE.
///
/// Wire format per chunk: `[4-byte BE length][12-byte IV][encrypted data]`
pub fn encrypt(data: &[u8]) -> EncryptResult {
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let key_b64 = B64.encode(key.as_slice());

    let mut out = Vec::new();

    for chunk in data.chunks(CHUNK_SIZE) {
        let nonce_bytes: [u8; IV_LENGTH] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, chunk)
            .expect("AES-256-GCM encryption failed");

        let chunk_len = (IV_LENGTH + ciphertext.len()) as u32;
        out.extend_from_slice(&chunk_len.to_be_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
    }

    EncryptResult {
        ciphertext: out,
        key_b64,
    }
}

/// Decrypt a ciphertext blob produced by `encrypt()`.
pub fn decrypt(ciphertext: &[u8], key_b64: &str) -> Result<Vec<u8>, &'static str> {
    let key_bytes = B64.decode(key_b64).map_err(|_| "invalid base64 key")?;
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
