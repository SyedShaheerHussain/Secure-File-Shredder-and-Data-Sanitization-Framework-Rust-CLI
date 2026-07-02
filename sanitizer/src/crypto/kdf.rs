//! Argon2id password-based key derivation, used to derive vault encryption
//! keys from user passphrases with memory-hard, side-channel-resistant
//! parameters.

use crate::crypto::rng::secure_random_bytes;
use crate::error::{Result, SanitizerError};
use argon2::{Algorithm, Argon2, Params, Version};

/// Derives a 32-byte key suitable for AES-256-GCM / XChaCha20-Poly1305 from
/// a passphrase and salt using Argon2id.
///
/// Parameters target ~256MB memory, 3 iterations, 4 lanes -- a reasonable
/// balance of brute-force resistance vs. usability for an interactive CLI
/// tool. Callers needing different cost can use `derive_key_with_params`.
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    derive_key_with_params(passphrase, salt, 256 * 1024, 3, 4)
}

pub fn derive_key_with_params(
    passphrase: &[u8],
    salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<[u8; 32]> {
    let params = Params::new(mem_kib, iterations, parallelism, Some(32))
        .map_err(|e| SanitizerError::Crypto(format!("invalid Argon2id parameters: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| SanitizerError::Crypto(format!("Argon2id derivation failed: {e}")))?;
    Ok(out)
}

pub fn generate_salt() -> Result<[u8; 16]> {
    let mut salt = [0u8; 16];
    secure_random_bytes(&mut salt)?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_given_same_salt() {
        let salt = [1u8; 16];
        let k1 = derive_key_with_params(b"correct horse battery staple", &salt, 8192, 2, 1).unwrap();
        let k2 = derive_key_with_params(b"correct horse battery staple", &salt, 8192, 2, 1).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_passwords_yield_different_keys() {
        let salt = [2u8; 16];
        let k1 = derive_key_with_params(b"password-one", &salt, 8192, 2, 1).unwrap();
        let k2 = derive_key_with_params(b"password-two", &salt, 8192, 2, 1).unwrap();
        assert_ne!(k1, k2);
    }
}
