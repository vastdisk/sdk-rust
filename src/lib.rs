/*!
# vastdisk-crypto

Public crypto primitives for VASTDISK - AES-256-GCM encryption/decryption,
BLAKE3 hashing, and Ed25519 signature verification.

Licensed under AGPLv3. See LICENSE for details.
*/

// Re-export everything from organized modules
pub mod constants;
pub mod types;
pub mod encryption;
pub mod hash;
pub mod verification;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(test)]
mod tests;

// Re-export public API
pub use constants::{IV_LENGTH, CHUNK_SIZE, LENGTH_PREFIX};
pub use types::{DeletionPayload, EncryptResult};
pub use encryption::{encrypt, decrypt};
pub use hash::hash_blake3;
pub use verification::verify_deletion_proof;

#[cfg(feature = "wasm")]
pub use wasm::{wasm_hash_blake3, wasm_verify_deletion_proof};
