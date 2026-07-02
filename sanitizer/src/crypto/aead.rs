//! Authenticated encryption primitives: AES-256-GCM and XChaCha20-Poly1305.
//! Used by the vault subsystem and for encrypted audit log storage.

use crate::crypto::rng::secure_random_bytes;
use crate::error::{Result, SanitizerError};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

pub const AES_KEY_LEN: usize = 32;
pub const AES_NONCE_LEN: usize = 12;
pub const XCHACHA_KEY_LEN: usize = 32;
pub const XCHACHA_NONCE_LEN: usize = 24;

/// Encrypt `plaintext` with AES-256-GCM under `key` (32 bytes), with
/// optional associated data bound to the ciphertext. Returns
/// (nonce, ciphertext_with_tag).
pub fn aes256gcm_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != AES_KEY_LEN {
        return Err(SanitizerError::Crypto("AES-256-GCM requires a 32-byte key".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SanitizerError::Crypto(format!("AES key init failed: {e}")))?;
    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    secure_random_bytes(&mut nonce_bytes)?;
    let nonce = AesNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| SanitizerError::Crypto(format!("AES-256-GCM encryption failed: {e}")))?;
    Ok((nonce_bytes.to_vec(), ct))
}

pub fn aes256gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES_KEY_LEN {
        return Err(SanitizerError::Crypto("AES-256-GCM requires a 32-byte key".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SanitizerError::Crypto(format!("AES key init failed: {e}")))?;
    let nonce = AesNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| SanitizerError::Crypto("AES-256-GCM decryption/authentication failed".into()))
}

/// Encrypt with XChaCha20-Poly1305 (extended 24-byte nonce, safe for random
/// nonce generation without birthday-bound collision concerns).
pub fn xchacha20poly1305_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != XCHACHA_KEY_LEN {
        return Err(SanitizerError::Crypto("XChaCha20-Poly1305 requires a 32-byte key".into()));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| SanitizerError::Crypto(format!("XChaCha key init failed: {e}")))?;
    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    secure_random_bytes(&mut nonce_bytes)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| SanitizerError::Crypto(format!("XChaCha20-Poly1305 encryption failed: {e}")))?;
    Ok((nonce_bytes.to_vec(), ct))
}

pub fn xchacha20poly1305_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if key.len() != XCHACHA_KEY_LEN {
        return Err(SanitizerError::Crypto("XChaCha20-Poly1305 requires a 32-byte key".into()));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| SanitizerError::Crypto(format!("XChaCha key init failed: {e}")))?;
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| SanitizerError::Crypto("XChaCha20-Poly1305 decryption/authentication failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_round_trip() {
        let key = vec![7u8; AES_KEY_LEN];
        let (nonce, ct) = aes256gcm_encrypt(&key, b"top secret", b"vault-v1").unwrap();
        let pt = aes256gcm_decrypt(&key, &nonce, &ct, b"vault-v1").unwrap();
        assert_eq!(pt, b"top secret");
    }

    #[test]
    fn aes_gcm_rejects_tampered_ciphertext() {
        let key = vec![3u8; AES_KEY_LEN];
        let (nonce, mut ct) = aes256gcm_encrypt(&key, b"data", b"").unwrap();
        ct[0] ^= 0xFF;
        assert!(aes256gcm_decrypt(&key, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn xchacha_round_trip() {
        let key = vec![9u8; XCHACHA_KEY_LEN];
        let (nonce, ct) = xchacha20poly1305_encrypt(&key, b"sensitive payload", b"").unwrap();
        let pt = xchacha20poly1305_decrypt(&key, &nonce, &ct, b"").unwrap();
        assert_eq!(pt, b"sensitive payload");
    }
}
