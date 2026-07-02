//! Cryptography subsystem: secure RNG, hashing (SHA-256/512, BLAKE3, HMAC),
//! authenticated encryption (AES-256-GCM, XChaCha20-Poly1305), Argon2id KDF,
//! and secure memory handling primitives.

pub mod rng;
pub mod hashing;
pub mod aead;
pub mod kdf;
pub mod secure_mem;

pub use rng::secure_random_bytes;
pub use secure_mem::SecureBytes;
