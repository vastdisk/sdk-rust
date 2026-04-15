use wasm_bindgen::prelude::*;

use crate::types::DeletionPayload;
use crate::hash::hash_blake3;
use crate::verification::verify_deletion_proof;

#[wasm_bindgen]
pub fn wasm_hash_blake3(data: &[u8]) -> String {
    hash_blake3(data)
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
    verify_deletion_proof(&payload, signature_b64, public_key_b64)
}
