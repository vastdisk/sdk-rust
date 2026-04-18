use crate::types::*;

pub fn hash(data: &[u8], algo: HashAlgorithm) -> String {
    match algo {
        HashAlgorithm::Blake3 => blake3::hash(data).to_hex().to_string(),
        HashAlgorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
    }
}

pub fn hash_blake3(data: &[u8]) -> String {
    hash(data, HashAlgorithm::Blake3)
}

pub fn hash_sha256(data: &[u8]) -> String {
    hash(data, HashAlgorithm::Sha256)
}
