use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::types::*;

pub fn verify_deletion_proof(
    payload: &DeletionPayload,
    signature_b64: &str,
    public_key_b64: &str,
) -> CryptoResult<()> {
    let payload_json = serde_json::to_string(payload).map_err(|_| CryptoError::InvalidSignature)?;

    let sig_bytes = B64.decode(signature_b64).map_err(|_| CryptoError::InvalidSignature)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| CryptoError::InvalidSignature)?;

    let pk_bytes = B64.decode(public_key_b64).map_err(|_| CryptoError::InvalidSignature)?;
    let pk_array: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| CryptoError::InvalidSignature)?;
    let verifying_key = VerifyingKey::from_bytes(&pk_array).map_err(|_| CryptoError::InvalidSignature)?;

    verifying_key
        .verify(payload_json.as_bytes(), &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_deletion_proof_json(
    payload_json: &str,
    signature_b64: &str,
    public_key_b64: &str,
) -> CryptoResult<()> {
    let sig_bytes = B64.decode(signature_b64).map_err(|_| CryptoError::InvalidSignature)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| CryptoError::InvalidSignature)?;

    let pk_bytes = B64.decode(public_key_b64).map_err(|_| CryptoError::InvalidSignature)?;
    let pk_array: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| CryptoError::InvalidSignature)?;
    let verifying_key = VerifyingKey::from_bytes(&pk_array).map_err(|_| CryptoError::InvalidSignature)?;

    verifying_key
        .verify(payload_json.as_bytes(), &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}
