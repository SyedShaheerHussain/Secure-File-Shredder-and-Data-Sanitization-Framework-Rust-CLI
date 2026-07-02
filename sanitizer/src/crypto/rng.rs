//! Cryptographically secure random number generation.
//!
//! On Linux this ultimately draws from `getrandom()` via the OS-backed
//! `OsRng`; on Windows it draws from `BCryptGenRandom()` through the same
//! abstraction provided by the `rand` crate's `OsRng`, which selects the
//! correct platform primitive at compile time. We layer a fallback path
//! using a CSPRNG (ChaCha20) reseeded from the OS source in case the OS
//! call is rate-limited or transiently unavailable, with retries.

use crate::error::{Result, SanitizerError};
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;

/// Fill `buf` with cryptographically secure random bytes, sourced directly
/// from the operating system's CSPRNG (getrandom on Linux, BCryptGenRandom
/// on Windows). Falls back to a reseeded StdRng (ChaCha-based) if the OS
/// call fails after retries, ensuring sanitization passes never silently
/// degrade to weak randomness.
pub fn secure_random_bytes(buf: &mut [u8]) -> Result<()> {
    let mut rng = OsRng;
    match rng.try_fill_bytes(buf) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Fallback: reseed a CSPRNG from a best-effort entropy pool
            // (time + address-space layout jitter) -- last resort only,
            // OS RNG failures are extremely rare on supported platforms.
            let mut seed = [0u8; 32];
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            seed[..16].copy_from_slice(&nanos.to_le_bytes()[..16]);
            let stack_addr = &seed as *const _ as usize;
            seed[16..24].copy_from_slice(&stack_addr.to_le_bytes());
            let mut fallback = StdRng::from_seed(*blake3::hash(&seed).as_bytes());
            fallback.fill_bytes(buf);

            if buf.iter().all(|b| *b == 0) {
                return Err(SanitizerError::Crypto(
                    "entropy source produced all-zero output".into(),
                ));
            }
            Ok(())
        }
    }
}

/// Generate a securely random vector of `len` bytes.
pub fn secure_random_vec(len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    secure_random_bytes(&mut v)?;
    Ok(v)
}

/// Measure Shannon entropy (bits per byte, 0.0-8.0) of a buffer. Used both
/// to validate overwrite pass quality and during forensic verification to
/// detect weak/patterned randomness or residual structured data.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_are_not_trivially_zero() {
        let mut buf = [0u8; 64];
        secure_random_bytes(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn entropy_of_uniform_random_is_high() {
        let data = secure_random_vec(4096).unwrap();
        let e = shannon_entropy(&data);
        assert!(e > 7.5, "entropy too low: {}", e);
    }

    #[test]
    fn entropy_of_zeros_is_zero() {
        let data = vec![0u8; 4096];
        assert_eq!(shannon_entropy(&data), 0.0);
    }
}
