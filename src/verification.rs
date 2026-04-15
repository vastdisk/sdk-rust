use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::types::DeletionPayload;

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

    let verifying_key =
        match VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap_or(&[0u8; 32])) {
            Ok(k) => k,
            Err(_) => return false,
        };

    verifying_key.verify(payload_json.as_bytes(), &sig).is_ok()
}
