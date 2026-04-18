use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use base64::Engine;

use crate::constants::{CHUNK_SIZE, IV_LENGTH, LENGTH_PREFIX};
use crate::types::EncryptResult;

const V2_MAGIC: [u8; 4] = *b"VAST";
const V2_VERSION: u8 = 2;
const V2_FILE_NONCE_LEN: usize = 16;
// magic(4) + version(1) + flags(1) + reserved(2) + file_nonce(16) = 24 bytes
const V2_HEADER_LEN: usize = 24;

fn encode_key_b64url(key: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
}

fn decode_key_b64_any(key: &str) -> Result<Vec<u8>, &'static str> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(key))
        .map_err(|_| "invalid base64 key")
}

fn is_v2_ciphertext(ciphertext: &[u8]) -> bool {
    ciphertext.len() >= V2_HEADER_LEN
        && ciphertext[0..4] == V2_MAGIC
        && ciphertext[4] == V2_VERSION
}

/// Encrypt a byte slice with AES-256-GCM, chunked at CHUNK_SIZE.
///
/// Wire format v2:
/// - Header: "VAST" + version + file nonce
/// - Chunks: `[4-byte BE length][12-byte IV][AES-256-GCM(ciphertext+tag)]`
///
/// v2 uses AES-GCM AAD to bind chunk order to the file header.
pub fn encrypt(data: &[u8]) -> EncryptResult {
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let key_b64 = encode_key_b64url(key.as_slice());

    let mut header = [0u8; V2_HEADER_LEN];
    header[0..4].copy_from_slice(&V2_MAGIC);
    header[4] = V2_VERSION;
    header[5] = 0; // flags (reserved)
    header[6] = 0; // reserved
    header[7] = 0; // reserved
    let file_nonce: [u8; V2_FILE_NONCE_LEN] = rand::random();
    header[8..8 + V2_FILE_NONCE_LEN].copy_from_slice(&file_nonce);

    let mut out = Vec::new();
    out.extend_from_slice(&header);

    for (chunk_index, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
        let nonce_bytes: [u8; IV_LENGTH] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut aad = [0u8; V2_HEADER_LEN + 4];
        aad[..V2_HEADER_LEN].copy_from_slice(&header);
        aad[V2_HEADER_LEN..].copy_from_slice(&(chunk_index as u32).to_be_bytes());

        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: chunk, aad: &aad })
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
    let key_bytes = decode_key_b64_any(key_b64)?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut out = Vec::new();
    let mut offset = 0;
    let mut header: Option<[u8; V2_HEADER_LEN]> = None;
    if is_v2_ciphertext(ciphertext) {
        let mut h = [0u8; V2_HEADER_LEN];
        h.copy_from_slice(&ciphertext[..V2_HEADER_LEN]);
        header = Some(h);
        offset = V2_HEADER_LEN;
    }
    let mut chunk_index: u32 = 0;

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
        let plaintext = if let Some(h) = header {
            let mut aad = [0u8; V2_HEADER_LEN + 4];
            aad[..V2_HEADER_LEN].copy_from_slice(&h);
            aad[V2_HEADER_LEN..].copy_from_slice(&chunk_index.to_be_bytes());
            cipher
                .decrypt(nonce, Payload { msg: enc_data, aad: &aad })
                .map_err(|_| "decryption failed (wrong key or corrupt data)")?
        } else {
            cipher
                .decrypt(nonce, enc_data)
                .map_err(|_| "decryption failed (wrong key or corrupt data)")?
        };
        out.extend_from_slice(&plaintext);
        chunk_index = chunk_index.wrapping_add(1);
    }

    Ok(out)
}
