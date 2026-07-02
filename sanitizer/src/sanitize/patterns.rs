//! Overwrite pattern strategies for the sanitization engine.

use crate::crypto::rng::secure_random_bytes;
use crate::error::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OverwritePattern {
    /// Single pass of cryptographically secure random data.
    SingleRandom,
    /// N passes of cryptographically secure random data.
    MultiRandom(u32),
    /// A DoD 5220.22-M-inspired three-pass scheme: 0x00, 0xFF, random,
    /// each pass followed by a verification read. Provided for
    /// completeness/compliance-checkbox purposes; modern guidance (NIST
    /// SP 800-88) treats a single good overwrite pass, or better, crypto
    /// erase, as sufficient on modern media.
    DodThreePass,
    /// NIST SP 800-88 Clear-equivalent: one pass of a fixed pattern.
    NistClear,
    /// NIST SP 800-88 Purge-equivalent: one random pass plus verification;
    /// for SSD/NVMe this is combined with a recommendation to use the
    /// device's native Sanitize/Secure Erase command instead.
    NistPurge,
    /// User-supplied byte pattern repeated to fill each pass.
    Custom(Vec<u8>),
    /// Zero fill (single pass of 0x00).
    Zeros,
    /// Ones fill (single pass of 0xFF).
    Ones,
}

impl OverwritePattern {
    pub fn passes(&self) -> u32 {
        match self {
            OverwritePattern::SingleRandom => 1,
            OverwritePattern::MultiRandom(n) => (*n).max(1),
            OverwritePattern::DodThreePass => 3,
            OverwritePattern::NistClear => 1,
            OverwritePattern::NistPurge => 1,
            OverwritePattern::Custom(_) => 1,
            OverwritePattern::Zeros => 1,
            OverwritePattern::Ones => 1,
        }
    }

    /// Fill `buf` for the given zero-indexed pass number according to this
    /// pattern's scheme.
    pub fn fill_pass(&self, buf: &mut [u8], pass_index: u32) -> Result<()> {
        match self {
            OverwritePattern::SingleRandom | OverwritePattern::MultiRandom(_) => {
                secure_random_bytes(buf)?;
            }
            OverwritePattern::DodThreePass => match pass_index {
                0 => buf.fill(0x00),
                1 => buf.fill(0xFF),
                _ => secure_random_bytes(buf)?,
            },
            OverwritePattern::NistClear => buf.fill(0x00),
            OverwritePattern::NistPurge => secure_random_bytes(buf)?,
            OverwritePattern::Custom(pattern) => {
                if pattern.is_empty() {
                    secure_random_bytes(buf)?;
                } else {
                    for (i, b) in buf.iter_mut().enumerate() {
                        *b = pattern[i % pattern.len()];
                    }
                }
            }
            OverwritePattern::Zeros => buf.fill(0x00),
            OverwritePattern::Ones => buf.fill(0xFF),
        }
        Ok(())
    }

    pub fn name(&self) -> String {
        match self {
            OverwritePattern::SingleRandom => "single-random".into(),
            OverwritePattern::MultiRandom(n) => format!("multi-random-{n}"),
            OverwritePattern::DodThreePass => "dod-5220.22-m-3pass".into(),
            OverwritePattern::NistClear => "nist-800-88-clear".into(),
            OverwritePattern::NistPurge => "nist-800-88-purge".into(),
            OverwritePattern::Custom(_) => "custom-pattern".into(),
            OverwritePattern::Zeros => "zeros".into(),
            OverwritePattern::Ones => "ones".into(),
        }
    }
}

impl std::str::FromStr for OverwritePattern {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "random" | "single-random" => Ok(OverwritePattern::SingleRandom),
            "dod" | "dod3" | "dod-5220.22-m" => Ok(OverwritePattern::DodThreePass),
            "nist-clear" => Ok(OverwritePattern::NistClear),
            "nist-purge" => Ok(OverwritePattern::NistPurge),
            "zeros" | "zero" => Ok(OverwritePattern::Zeros),
            "ones" | "one" => Ok(OverwritePattern::Ones),
            other => {
                if let Some(n) = other.strip_prefix("multi-random-") {
                    n.parse::<u32>()
                        .map(OverwritePattern::MultiRandom)
                        .map_err(|_| format!("invalid pass count in '{other}'"))
                } else {
                    Err(format!("unknown overwrite pattern: '{other}' (try: random, dod, nist-clear, nist-purge, zeros, ones, multi-random-N)"))
                }
            }
        }
    }
}
