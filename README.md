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

Each encrypted chunk: `[4-byte BE length][12-byte IV][AES-256-GCM ciphertext]`

Multiple chunks are concatenated.

## License

AGPLv3 — see [LICENSE](./LICENSE). Crypto code is open for audit.
