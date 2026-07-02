//! Hashing primitives used for integrity verification, audit log chaining,
//! and content fingerprinting: SHA-256, SHA-512, BLAKE3, and HMAC-SHA256.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn sha512_hex(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Streaming BLAKE3 hash of a file-like reader, used for large-file
/// integrity checks without loading the whole file into memory.
pub fn blake3_hash_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 1 << 16];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

type HmacSha256 = Hmac<Sha256>;

/// Compute an HMAC-SHA256 tag over `data` using `key`, used to chain and
/// authenticate audit log entries (tamper-evident logging).
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag_hex: &str) -> bool {
    match hex::decode(tag_hex) {
        Ok(tag_bytes) => {
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
            mac.update(data);
            mac.verify_slice(&tag_bytes).is_ok()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_round_trips() {
        let key = b"audit-log-key";
        let data = b"some log entry";
        let tag = hmac_sha256_hex(key, data);
        assert!(hmac_sha256_verify(key, data, &tag));
        assert!(!hmac_sha256_verify(key, b"tampered entry", &tag));
    }

    #[test]
    fn blake3_is_deterministic() {
        let a = blake3_hex(b"hello world");
        let b = blake3_hex(b"hello world");
        assert_eq!(a, b);
    }
}
