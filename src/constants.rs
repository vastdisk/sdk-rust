/// AES-256-GCM nonce length (12 bytes).
pub const IV_LENGTH: usize = 12;

/// Chunk size used for streaming encryption (1 MB).
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Length prefix size (4 bytes, big-endian u32).
pub const LENGTH_PREFIX: usize = 4;
