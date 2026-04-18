# vastdisk-crypto

Rust crypto core for [VASTDISK](https://vastdisk.com). Licensed under **AGPLv3** for full transparency and auditability.

## What It Provides

- **AES-256-GCM** chunked encryption/decryption (1 MB chunks, random IV per chunk)
- **BLAKE3** hashing
- **Ed25519** signature verification (for deletion proofs)
- Optional **WASM bindings** via `wasm-bindgen`

## Usage

```rust
use vastdisk_crypto::{encrypt, decrypt, hash_blake3, verify_deletion_proof, DeletionPayload};

// Encrypt
let result = encrypt(b"secret data");
println!("key: {}", result.key_b64);

// Decrypt
let plaintext = decrypt(&result.ciphertext, &result.key_b64).unwrap();

// Hash
let hash = hash_blake3(b"some data");

// Verify deletion proof
let valid = verify_deletion_proof(&payload, &signature_b64, &public_key_b64);
```

## WASM

Build with `--features wasm` and use `wasm-pack build`:

```bash
wasm-pack build --features wasm --target web
```

## Wire Format

V2 ciphertexts start with a fixed header, then chunk records:

- Header: `[4-byte "VAST"][1-byte version=2][3 reserved bytes][16-byte file nonce]`
- Each encrypted chunk: `[4-byte BE length][12-byte IV][AES-256-GCM ciphertext+tag]`

Chunks are authenticated with AES-GCM **additional authenticated data (AAD)** that binds the header and chunk index.

Legacy v1 ciphertexts (no header / no AAD binding) are rejected by default.

## License

AGPLv3 - see [LICENSE](./LICENSE). Crypto code is open for audit.
