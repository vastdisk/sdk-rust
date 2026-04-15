use serde::{Deserialize, Serialize};

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
