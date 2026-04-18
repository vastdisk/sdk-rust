use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::constants::*;
use crate::types::*;

const V2_MAGIC: [u8; 4] = *b"VAST";
const V2_VERSION: u8 = 2;
const V2_FILE_NONCE_LEN: usize = 16;
const V2_HEADER_LEN: usize = 24;

fn encode_key_b64url(key: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
}

fn decode_key_b64_any(key: &str) -> CryptoResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(key))
        .map_err(|_| CryptoError::InvalidKey)
}

fn is_v2_ciphertext(ciphertext: &[u8]) -> bool {
    ciphertext.len() >= V2_HEADER_LEN
        && ciphertext[0..4] == V2_MAGIC
        && ciphertext[4] == V2_VERSION
}

pub fn validate_key(key_b64: &str) -> CryptoResult<Vec<u8>> {
    let key = decode_key_b64_any(key_b64)?;
    if key.len() != KEY_LENGTH_BYTES {
        return Err(CryptoError::InvalidKey);
    }
    Ok(key)
}

pub fn validate_ciphertext(ciphertext: &[u8]) -> CryptoResult<()> {
    if ciphertext.len() < V2_HEADER_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }
    if !is_v2_ciphertext(ciphertext) {
        return Err(CryptoError::InvalidCiphertext);
    }
    let mut offset = V2_HEADER_LEN;
    while offset + LENGTH_PREFIX <= ciphertext.len() {
        let chunk_len = u32::from_be_bytes(
            ciphertext[offset..offset + LENGTH_PREFIX]
                .try_into()
                .map_err(|_| CryptoError::InvalidCiphertext)?,
        ) as usize;
        offset += LENGTH_PREFIX;
        if offset + chunk_len > ciphertext.len() {
            return Err(CryptoError::InvalidCiphertext);
        }
        if chunk_len < IV_LENGTH + 16 {
            return Err(CryptoError::InvalidCiphertext);
        }
        offset += chunk_len;
    }
    Ok(())
}

pub struct CiphertextMetadata {
    pub version: u8,
    pub chunk_count: u32,
    pub total_size: usize,
}

pub fn get_ciphertext_metadata(ciphertext: &[u8]) -> CryptoResult<CiphertextMetadata> {
    if !is_v2_ciphertext(ciphertext) {
        return Err(CryptoError::InvalidCiphertext);
    }
    let version = ciphertext[4];
    let mut offset = V2_HEADER_LEN;
    let mut chunk_count: u32 = 0;
    while offset + LENGTH_PREFIX <= ciphertext.len() {
        let chunk_len = u32::from_be_bytes(
            ciphertext[offset..offset + LENGTH_PREFIX]
                .try_into()
                .map_err(|_| CryptoError::InvalidCiphertext)?,
        ) as usize;
        offset += LENGTH_PREFIX + chunk_len;
        chunk_count += 1;
    }
    Ok(CiphertextMetadata {
        version,
        chunk_count,
        total_size: ciphertext.len(),
    })
}

pub fn reencrypt(ciphertext: &[u8], old_key_b64: &str) -> CryptoResult<EncryptResult> {
    let plaintext = decrypt(ciphertext, old_key_b64)?;
    encrypt(&plaintext)
}

pub fn encrypt(data: &[u8]) -> CryptoResult<EncryptResult> {
    encrypt_with_opts(data, &EncryptOptions::default())
}

pub fn encrypt_with_opts(data: &[u8], opts: &EncryptOptions) -> CryptoResult<EncryptResult> {
    let mut rng = OsRng;
    let key = Aes256Gcm::generate_key(&mut rng);
    let cipher = Aes256Gcm::new(&key);
    let key_b64 = encode_key_b64url(key.as_slice());

    let mut header = [0u8; V2_HEADER_LEN];
    header[0..4].copy_from_slice(&V2_MAGIC);
    header[4] = V2_VERSION;
    header[5] = 0;
    header[6] = 0;
    header[7] = 0;
    let mut file_nonce = [0u8; V2_FILE_NONCE_LEN];
    rng.fill_bytes(&mut file_nonce);
    header[8..8 + V2_FILE_NONCE_LEN].copy_from_slice(&file_nonce);

    let mut out = Vec::new();
    out.extend_from_slice(&header);

    for (chunk_index, chunk) in data.chunks(opts.chunk_size).enumerate() {
        if chunk_index > u32::MAX as usize {
            return Err(CryptoError::EncryptionFailed);
        }

        let mut nonce_bytes = [0u8; IV_LENGTH];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut aad = [0u8; V2_HEADER_LEN + 4];
        aad[..V2_HEADER_LEN].copy_from_slice(&header);
        aad[V2_HEADER_LEN..].copy_from_slice(&(chunk_index as u32).to_be_bytes());

        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: chunk, aad: &aad })
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let chunk_len = (IV_LENGTH + ciphertext.len()) as u32;
        out.extend_from_slice(&chunk_len.to_be_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
    }

    Ok(EncryptResult {
        ciphertext: out,
        key_b64,
    })
}

pub fn decrypt(ciphertext: &[u8], key_b64: &str) -> CryptoResult<Vec<u8>> {
    decrypt_with_opts(ciphertext, key_b64, &DecryptOptions::default())
}

pub fn decrypt_with_opts(ciphertext: &[u8], key_b64: &str, opts: &DecryptOptions) -> CryptoResult<Vec<u8>> {
    let key_bytes = validate_key(key_b64)?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes[..]);
    let cipher = Aes256Gcm::new(key);

    let mut out = Vec::new();
    let mut offset = 0;
    let mut header: Option<[u8; V2_HEADER_LEN]> = None;
    if is_v2_ciphertext(ciphertext) {
        let mut h = [0u8; V2_HEADER_LEN];
        h.copy_from_slice(&ciphertext[..V2_HEADER_LEN]);
        header = Some(h);
        offset = V2_HEADER_LEN;
    } else if !opts.allow_legacy_v1 {
        // Legacy v1 format had no header/AAD binding; reject by default.
        return Err(CryptoError::InvalidCiphertext);
    }
    let mut chunk_index: u32 = 0;

    while offset + LENGTH_PREFIX <= ciphertext.len() {
        let chunk_len = u32::from_be_bytes(
            ciphertext[offset..offset + LENGTH_PREFIX]
                .try_into()
                .map_err(|_| CryptoError::InvalidCiphertext)?,
        ) as usize;
        offset += LENGTH_PREFIX;

        if chunk_len < IV_LENGTH + 16 {
            return Err(CryptoError::InvalidCiphertext);
        }
        if offset + chunk_len > ciphertext.len() {
            return Err(CryptoError::InvalidCiphertext);
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
                .map_err(|_| CryptoError::DecryptionFailed)?
        } else {
            cipher
                .decrypt(nonce, enc_data)
                .map_err(|_| CryptoError::DecryptionFailed)?
        };
        out.extend_from_slice(&plaintext);
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or(CryptoError::InvalidCiphertext)?;
    }

    // Reject trailing garbage (Rust previously ignored <4 tail bytes).
    if offset != ciphertext.len() {
        return Err(CryptoError::InvalidCiphertext);
    }

    Ok(out)
}

pub fn encrypt_stream<R: std::io::Read>(reader: R, opts: &EncryptOptions) -> CryptoResult<EncryptResult> {
    let mut rng = OsRng;
    let key = Aes256Gcm::generate_key(&mut rng);
    let cipher = Aes256Gcm::new(&key);
    let key_b64 = encode_key_b64url(key.as_slice());

    let mut header = [0u8; V2_HEADER_LEN];
    header[0..4].copy_from_slice(&V2_MAGIC);
    header[4] = V2_VERSION;
    header[5] = 0;
    header[6] = 0;
    header[7] = 0;
    let mut file_nonce = [0u8; V2_FILE_NONCE_LEN];
    rng.fill_bytes(&mut file_nonce);
    header[8..8 + V2_FILE_NONCE_LEN].copy_from_slice(&file_nonce);

    let mut out = Vec::new();
    out.extend_from_slice(&header);

    let mut buffer = vec![0u8; opts.chunk_size];
    let mut chunk_index: u32 = 0;
    let mut reader = reader;

    loop {
        let n = reader.read(&mut buffer).map_err(|e| CryptoError::IoError(e.to_string()))?;
        if n == 0 {
            break;
        }
        let chunk = &buffer[..n];

        let mut nonce_bytes = [0u8; IV_LENGTH];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut aad = [0u8; V2_HEADER_LEN + 4];
        aad[..V2_HEADER_LEN].copy_from_slice(&header);
        aad[V2_HEADER_LEN..].copy_from_slice(&chunk_index.to_be_bytes());

        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: chunk, aad: &aad })
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let chunk_len = (IV_LENGTH + ciphertext.len()) as u32;
        out.extend_from_slice(&chunk_len.to_be_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        chunk_index = chunk_index
            .checked_add(1)
            .ok_or(CryptoError::EncryptionFailed)?;
    }

    Ok(EncryptResult {
        ciphertext: out,
        key_b64,
    })
}

pub fn decrypt_stream<R: std::io::Read, W: std::io::Write>(
    reader: R,
    mut writer: W,
    key_b64: &str,
) -> CryptoResult<()> {
    let key_bytes = validate_key(key_b64)?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes[..]);
    let cipher = Aes256Gcm::new(key);

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut ciphertext_buffer = Vec::new();
    let mut reader = reader;

    loop {
        let n = reader.read(&mut buffer).map_err(|e| CryptoError::IoError(e.to_string()))?;
        if n == 0 {
            break;
        }
        ciphertext_buffer.extend_from_slice(&buffer[..n]);
    }

    if !is_v2_ciphertext(&ciphertext_buffer) {
        return Err(CryptoError::InvalidCiphertext);
    }
    let mut h = [0u8; V2_HEADER_LEN];
    h.copy_from_slice(&ciphertext_buffer[..V2_HEADER_LEN]);
    let header: Option<[u8; V2_HEADER_LEN]> = Some(h);
    let mut offset = V2_HEADER_LEN;
    let mut chunk_index: u32 = 0;

    while offset + LENGTH_PREFIX <= ciphertext_buffer.len() {
        let chunk_len = u32::from_be_bytes(
            ciphertext_buffer[offset..offset + LENGTH_PREFIX]
                .try_into()
                .map_err(|_| CryptoError::InvalidCiphertext)?,
        ) as usize;
        offset += LENGTH_PREFIX;

        if chunk_len < IV_LENGTH + 16 {
            return Err(CryptoError::InvalidCiphertext);
        }
        if offset + chunk_len > ciphertext_buffer.len() {
            return Err(CryptoError::InvalidCiphertext);
        }

        let iv = &ciphertext_buffer[offset..offset + IV_LENGTH];
        offset += IV_LENGTH;

        let enc_data_len = chunk_len - IV_LENGTH;
        let enc_data = &ciphertext_buffer[offset..offset + enc_data_len];
        offset += enc_data_len;

        let nonce = Nonce::from_slice(iv);
        let plaintext = if let Some(h) = header {
            let mut aad = [0u8; V2_HEADER_LEN + 4];
            aad[..V2_HEADER_LEN].copy_from_slice(&h);
            aad[V2_HEADER_LEN..].copy_from_slice(&chunk_index.to_be_bytes());
            cipher
                .decrypt(nonce, Payload { msg: enc_data, aad: &aad })
                .map_err(|_| CryptoError::DecryptionFailed)?
        } else {
            cipher
                .decrypt(nonce, enc_data)
                .map_err(|_| CryptoError::DecryptionFailed)?
        };
        writer.write_all(&plaintext).map_err(|e| CryptoError::IoError(e.to_string()))?;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or(CryptoError::InvalidCiphertext)?;
    }

    if offset != ciphertext_buffer.len() {
        return Err(CryptoError::InvalidCiphertext);
    }

    Ok(())
}
