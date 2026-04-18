use wasm_bindgen::prelude::*;

use crate::types::*;
use crate::hash::*;
use crate::verification::*;

#[wasm_bindgen]
pub fn wasm_hash_blake3(data: &[u8]) -> String {
    hash_blake3(data)
}

#[wasm_bindgen]
pub fn wasm_hash_sha256(data: &[u8]) -> String {
    hash_sha256(data)
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
    verify_deletion_proof(&payload, signature_b64, public_key_b64).is_ok()
}

#[wasm_bindgen]
pub fn wasm_verify_deletion_proof_json(
    payload_json: &str,
    signature_b64: &str,
    public_key_b64: &str,
) -> bool {
    verify_deletion_proof_json(payload_json, signature_b64, public_key_b64).is_ok()
}
