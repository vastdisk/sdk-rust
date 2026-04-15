/// Hash data with BLAKE3 and return the hex-encoded digest.
pub fn hash_blake3(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}
