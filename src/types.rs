use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionPayload {
    pub file_id: String,
    pub file_hash: String,
    pub deleted_at: String,
    pub deletion_reason: String,
}

#[derive(Debug)]
pub enum CryptoError {
    InvalidKey,
    InvalidCiphertext,
    EncryptionFailed,
    DecryptionFailed,
    InvalidSignature,
    IoError(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKey => write!(f, "Invalid key"),
            CryptoError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

pub type CryptoResult<T> = Result<T, CryptoError>;

pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub key_b64: String,
}

pub struct EncryptOptions {
    pub chunk_size: usize,
    pub compress: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024,
            compress: false,
        }
    }
}

pub struct DecryptOptions {
    /// Legacy v1 ciphertexts did not include the V2 header / AAD binding.
    /// Keep this `false` by default to prevent accepting weakly-bound ciphertexts.
    pub allow_legacy_v1: bool,
}

impl Default for DecryptOptions {
    fn default() -> Self {
        Self {
            allow_legacy_v1: false,
        }
    }
}

pub enum HashAlgorithm {
    Blake3,
    Sha256,
}

pub enum EncryptionAlgorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
}
