//! Forensic verification engine: after sanitization, attempt controlled
//! "recovery" techniques against the target region (signature scanning,
//! simple file carving, magic-byte detection, string search, entropy
//! analysis) and produce a confidence score describing how likely
//! meaningful data recovery would be. Also exposed standalone via
//! `sanitizer recover <file>` as an educational research mode.

use crate::crypto::rng::shannon_entropy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Common file signatures ("magic bytes") checked for during carving --
/// their presence in supposedly-sanitized data is a strong signal of
/// incomplete destruction.
const MAGIC_SIGNATURES: &[(&str, &[u8])] = &[
    ("PDF", b"%PDF"),
    ("ZIP/DOCX/XLSX/JAR", &[0x50, 0x4B, 0x03, 0x04]),
    ("PNG", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    ("JPEG", &[0xFF, 0xD8, 0xFF]),
    ("GIF", b"GIF8"),
    ("ELF", &[0x7F, 0x45, 0x4C, 0x46]),
    ("Windows PE/EXE", &[0x4D, 0x5A]),
    ("SQLite DB", b"SQLite format 3\0"),
    ("Windows Registry Hive", b"regf"),
    ("BZip2", b"BZh"),
    ("Gzip", &[0x1F, 0x8B]),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub path: PathBuf,
    pub bytes_examined: u64,
    pub entropy: f64,
    pub signature_hits: Vec<String>,
    pub ascii_strings_found: usize,
    pub sample_strings: Vec<String>,
    pub recovery_confidence: RecoveryConfidence,
    pub confidence_score: f64,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryConfidence {
    /// High entropy, no signatures, no meaningful strings: sanitization
    /// appears effective.
    VeryLow,
    Low,
    Moderate,
    /// Signatures or long strings detected: sanitization likely
    /// incomplete or the medium did not honor the overwrite.
    High,
}

impl std::fmt::Display for RecoveryConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RecoveryConfidence::VeryLow => "Very Low",
            RecoveryConfidence::Low => "Low",
            RecoveryConfidence::Moderate => "Moderate",
            RecoveryConfidence::High => "High",
        };
        write!(f, "{s}")
    }
}

/// Run forensic verification against the raw bytes currently occupying
/// `path` (typically a file that has just been overwritten, or a raw
/// image/device path passed for research-mode testing). This is a
/// userspace-level analysis of file content; it does not perform actual
/// physical-media data recovery (which would require raw device access
/// and undelete/carving against unallocated space, a much larger scope),
/// but it does meaningfully detect whether *this* file's current content
/// still contains recognizable structured data.
pub fn verify_sanitization(path: &Path) -> crate::error::Result<VerificationReport> {
    let data = std::fs::read(path).map_err(|e| crate::error::SanitizerError::io(path, e))?;
    Ok(analyze_bytes(path, &data))
}

pub fn analyze_bytes(path: &Path, data: &[u8]) -> VerificationReport {
    let entropy = shannon_entropy(data);

    let mut signature_hits = Vec::new();
    for (name, magic) in MAGIC_SIGNATURES {
        if contains_subsequence(data, magic) {
            signature_hits.push((*name).to_string());
        }
    }

    let strings = extract_ascii_strings(data, 6);
    let ascii_strings_found = strings.len();
    let sample_strings: Vec<String> = strings.into_iter().take(10).collect();

    let recovery_confidence = classify_confidence(entropy, &signature_hits, ascii_strings_found);
    let confidence_score = confidence_to_score(recovery_confidence, entropy, &signature_hits, ascii_strings_found);

    let summary = build_summary(recovery_confidence, entropy, &signature_hits, ascii_strings_found);

    VerificationReport {
        path: path.to_path_buf(),
        bytes_examined: data.len() as u64,
        entropy,
        signature_hits,
        ascii_strings_found,
        sample_strings,
        recovery_confidence,
        confidence_score,
        summary,
    }
}

fn classify_confidence(entropy: f64, signatures: &[String], string_count: usize) -> RecoveryConfidence {
    if !signatures.is_empty() {
        return RecoveryConfidence::High;
    }
    if string_count > 50 {
        return RecoveryConfidence::High;
    }
    if entropy < 5.0 {
        return RecoveryConfidence::Moderate;
    }
    if string_count > 5 || entropy < 6.5 {
        return RecoveryConfidence::Low;
    }
    RecoveryConfidence::VeryLow
}

/// Map the qualitative confidence bucket plus its underlying signals to a
/// 0.0-1.0 "likelihood of successful recovery" score for reporting.
fn confidence_to_score(bucket: RecoveryConfidence, entropy: f64, signatures: &[String], string_count: usize) -> f64 {
    let base = match bucket {
        RecoveryConfidence::VeryLow => 0.02,
        RecoveryConfidence::Low => 0.15,
        RecoveryConfidence::Moderate => 0.45,
        RecoveryConfidence::High => 0.85,
    };
    let sig_bonus = (signatures.len() as f64 * 0.03).min(0.1);
    let string_bonus = ((string_count as f64) / 1000.0).min(0.05);
    let entropy_penalty = if entropy > 7.9 { -0.02 } else { 0.0 };
    (base + sig_bonus + string_bonus + entropy_penalty).clamp(0.0, 1.0)
}

fn build_summary(bucket: RecoveryConfidence, entropy: f64, signatures: &[String], string_count: usize) -> String {
    match bucket {
        RecoveryConfidence::VeryLow => format!(
            "No recognizable file signatures or meaningful strings detected; measured entropy {entropy:.2} bits/byte is consistent with a fully randomized overwrite. Recovery of the original content from this data is very unlikely."
        ),
        RecoveryConfidence::Low => format!(
            "Entropy {entropy:.2} bits/byte with {string_count} short ASCII strings detected; no known file signatures found. Sanitization appears largely effective, though the region isn't perfectly random."
        ),
        RecoveryConfidence::Moderate => format!(
            "Entropy {entropy:.2} bits/byte is lower than expected for a random overwrite pass, suggesting structured or non-random residual data. Recommend re-running sanitization or investigating filesystem copy-on-write/journaling behavior."
        ),
        RecoveryConfidence::High => format!(
            "Detected {} recognizable file signature(s) and {} ASCII string(s) of length >= 6 in the target region. Sanitization is very likely incomplete -- original or related data may still be recoverable.",
            signatures.len(),
            string_count
        ),
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Extract printable ASCII runs of at least `min_len` bytes -- a simple
/// analog of the Unix `strings` utility, used to detect residual
/// human-readable text (filenames, document fragments, credentials) left
/// behind after sanitization.
fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if (0x20..=0x7E).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_len {
                results.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        results.push(String::from_utf8_lossy(&current).to_string());
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pdf_signature() {
        let mut data = vec![0u8; 100];
        data[10..14].copy_from_slice(b"%PDF");
        let report = analyze_bytes(Path::new("test"), &data);
        assert!(report.signature_hits.contains(&"PDF".to_string()));
        assert_eq!(report.recovery_confidence, RecoveryConfidence::High);
    }

    #[test]
    fn random_data_scores_low_confidence() {
        let data: Vec<u8> = (0..4096u64).map(|i| ((i.wrapping_mul(2654435761)) % 256) as u8).collect();
        let report = analyze_bytes(Path::new("test"), &data);
        assert!(report.signature_hits.is_empty());
    }

    #[test]
    fn detects_ascii_strings() {
        let mut data = vec![0u8; 20];
        data.extend_from_slice(b"password123secret");
        data.extend(vec![0u8; 20]);
        let strings = extract_ascii_strings(&data, 6);
        assert!(!strings.is_empty());
    }
}
