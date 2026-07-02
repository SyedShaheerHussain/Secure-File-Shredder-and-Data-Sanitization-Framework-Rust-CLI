//! Secure audit logging: structured JSON log entries, cryptographically
//! chained via HMAC-SHA256 (each entry's tag covers the previous entry's
//! tag, forming a tamper-evident hash chain analogous to a mini
//! blockchain), with optional AES-256-GCM-encrypted storage at rest.

use crate::crypto::aead::{aes256gcm_decrypt, aes256gcm_encrypt};
use crate::crypto::hashing::hmac_sha256_hex;
use crate::crypto::kdf::derive_key;
use crate::error::{Result, SanitizerError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub operation: String,
    pub target: String,
    pub details: serde_json::Value,
    pub prev_hash: String,
    pub entry_hmac: String,
}

pub struct AuditLog {
    path: PathBuf,
    hmac_key: Vec<u8>,
    last_hash: String,
    next_sequence: u64,
    encrypt_at_rest: bool,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000000000000000";

impl AuditLog {
    /// Open (creating if absent) an audit log at `path`, authenticated
    /// with a key derived from `key_material` (e.g. a passphrase or a
    /// machine-specific secret). `encrypt_at_rest` additionally encrypts
    /// each serialized entry line with AES-256-GCM before writing.
    pub fn open(path: &Path, key_material: &[u8], encrypt_at_rest: bool) -> Result<Self> {
        let salt = b"sanitizer-audit-log-salt-v1-fix";
        let hmac_key = derive_key(key_material, salt)?.to_vec();

        let (last_hash, next_sequence) = if path.exists() {
            Self::replay_and_verify(path, &hmac_key, encrypt_at_rest)?
        } else {
            (GENESIS_HASH.to_string(), 0)
        };

        Ok(AuditLog {
            path: path.to_path_buf(),
            hmac_key,
            last_hash,
            next_sequence,
            encrypt_at_rest,
        })
    }

    /// Append a new, chained, authenticated entry to the log.
    pub fn record(&mut self, operation: &str, target: &str, details: serde_json::Value) -> Result<()> {
        let entry_no_hmac = AuditEntry {
            sequence: self.next_sequence,
            timestamp: Utc::now(),
            operation: operation.to_string(),
            target: target.to_string(),
            details,
            prev_hash: self.last_hash.clone(),
            entry_hmac: String::new(),
        };

        let signing_bytes = canonical_signing_bytes(&entry_no_hmac);
        let tag = hmac_sha256_hex(&self.hmac_key, &signing_bytes);

        let mut entry = entry_no_hmac;
        entry.entry_hmac = tag.clone();

        let line = serde_json::to_vec(&entry)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| SanitizerError::io(&self.path, e))?;

        if self.encrypt_at_rest {
            let (nonce, ciphertext) = aes256gcm_encrypt(&self.hmac_key, &line, b"audit-log")?;
            let record = serde_json::json!({ "nonce": hex::encode(nonce), "ct": hex::encode(ciphertext) });
            writeln!(file, "{}", serde_json::to_string(&record)?).map_err(|e| SanitizerError::io(&self.path, e))?;
        } else {
            file.write_all(&line).map_err(|e| SanitizerError::io(&self.path, e))?;
            writeln!(file).map_err(|e| SanitizerError::io(&self.path, e))?;
        }

        self.last_hash = tag;
        self.next_sequence += 1;
        Ok(())
    }

    /// Replay the entire log verifying the HMAC chain, returning the last
    /// verified hash and next sequence number. Returns an error if any
    /// entry's tag doesn't match or the chain of `prev_hash` links is
    /// broken -- either indicates tampering.
    fn replay_and_verify(path: &Path, hmac_key: &[u8], encrypted: bool) -> Result<(String, u64)> {
        let content = std::fs::read_to_string(path).map_err(|e| SanitizerError::io(path, e))?;
        let mut last_hash = GENESIS_HASH.to_string();
        let mut expected_seq = 0u64;

        for (line_no, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = if encrypted {
                let record: serde_json::Value = serde_json::from_str(line)?;
                let nonce = hex::decode(record["nonce"].as_str().unwrap_or_default())
                    .map_err(|_| SanitizerError::Crypto("bad nonce hex in audit log".into()))?;
                let ct = hex::decode(record["ct"].as_str().unwrap_or_default())
                    .map_err(|_| SanitizerError::Crypto("bad ciphertext hex in audit log".into()))?;
                let pt = aes256gcm_decrypt(hmac_key, &nonce, &ct, b"audit-log")?;
                serde_json::from_slice(&pt)?
            } else {
                serde_json::from_str(line)?
            };

            if entry.sequence != expected_seq {
                return Err(SanitizerError::Verification(format!(
                    "audit log tamper detected: sequence gap at line {} (expected {}, got {})",
                    line_no + 1,
                    expected_seq,
                    entry.sequence
                )));
            }
            if entry.prev_hash != last_hash {
                return Err(SanitizerError::Verification(format!(
                    "audit log tamper detected: broken hash chain at sequence {}",
                    entry.sequence
                )));
            }

            let mut check_entry = entry.clone();
            check_entry.entry_hmac = String::new();
            let signing_bytes = canonical_signing_bytes(&check_entry);
            let expected_tag = hmac_sha256_hex(hmac_key, &signing_bytes);
            if expected_tag != entry.entry_hmac {
                return Err(SanitizerError::Verification(format!(
                    "audit log tamper detected: HMAC mismatch at sequence {}",
                    entry.sequence
                )));
            }

            last_hash = entry.entry_hmac.clone();
            expected_seq += 1;
        }

        Ok((last_hash, expected_seq))
    }

    /// Verify the on-disk log's integrity without mutating in-memory
    /// state; useful for a standalone `sanitizer report --verify-audit`
    /// command.
    pub fn verify_file(path: &Path, key_material: &[u8], encrypted: bool) -> Result<u64> {
        let salt = b"sanitizer-audit-log-salt-v1-fix";
        let hmac_key = derive_key(key_material, salt)?.to_vec();
        let (_, count) = Self::replay_and_verify(path, &hmac_key, encrypted)?;
        Ok(count)
    }
}

fn canonical_signing_bytes(entry: &AuditEntry) -> Vec<u8> {
    // Deterministic signing representation: exclude entry_hmac itself,
    // include everything else in a fixed field order (rather than relying
    // on serde_json's map ordering for `details`, which could vary).
    format!(
        "{}|{}|{}|{}|{}|{}",
        entry.sequence,
        entry.timestamp.to_rfc3339(),
        entry.operation,
        entry.target,
        entry.details,
        entry.prev_hash
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile_shim::TempPath;

    mod tempfile_shim {
        use std::path::PathBuf;
        pub struct TempPath(pub PathBuf);
        impl TempPath {
            pub fn new(name: &str) -> Self {
                let mut p = std::env::temp_dir();
                p.push(format!("sanitizer_test_{}_{}", std::process::id(), name));
                TempPath(p)
            }
        }
        impl Drop for TempPath {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
    }

    #[test]
    fn chained_log_verifies() {
        let tmp = TempPath::new("audit1.log");
        let mut log = AuditLog::open(&tmp.0, b"test-key", false).unwrap();
        log.record("wipe", "/tmp/a", serde_json::json!({"passes": 1})).unwrap();
        log.record("wipe", "/tmp/b", serde_json::json!({"passes": 3})).unwrap();
        drop(log);

        let count = AuditLog::verify_file(&tmp.0, b"test-key", false).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn tampered_log_fails_verification() {
        let tmp = TempPath::new("audit2.log");
        let mut log = AuditLog::open(&tmp.0, b"test-key", false).unwrap();
        log.record("wipe", "/tmp/a", serde_json::json!({})).unwrap();
        drop(log);

        let mut content = std::fs::read_to_string(&tmp.0).unwrap();
        content = content.replace("\"wipe\"", "\"tampered\"");
        std::fs::write(&tmp.0, content).unwrap();

        assert!(AuditLog::verify_file(&tmp.0, b"test-key", false).is_err());
    }
}
