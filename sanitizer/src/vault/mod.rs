//! Secure encrypted vault: create an encrypted container protected by an
//! Argon2id-derived key, add/extract files with authenticated encryption,
//! and securely destroy the vault (overwrite + delete + key zeroization).

use crate::crypto::aead::{aes256gcm_decrypt, aes256gcm_encrypt};
use crate::crypto::kdf::{derive_key, generate_salt};
use crate::crypto::rng::secure_random_vec;
use crate::crypto::secure_mem::SecureBytes;
use crate::error::{Result, SanitizerError};
use crate::sanitize::engine::{shred_file, ShredOptions};
use crate::sanitize::patterns::OverwritePattern;
use crate::storage::device::detect_storage_for_path;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const VAULT_MAGIC: &[u8; 8] = b"SANIVLT1";

/// On-disk vault format:
///   [8-byte magic][16-byte salt][4-byte header_len LE][header_json (encrypted separately? no - header is plaintext metadata)]
/// We store an encrypted blob: header (JSON) is itself encrypted alongside
/// entries under the same derived key, since even filenames within the
/// vault are considered sensitive.
#[derive(Debug, Serialize, Deserialize, Default)]
struct VaultHeader {
    entries: HashMap<String, EntryMeta>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EntryMeta {
    original_name: String,
    size: u64,
    sha256: String,
}

pub struct Vault {
    pub path: PathBuf,
    key: SecureBytes,
    salt: [u8; 16],
    header: VaultHeader,
}

impl Vault {
    /// Create a new, empty encrypted vault at `path`, protected by
    /// `passphrase` via Argon2id -> AES-256-GCM.
    pub fn create(path: &Path, passphrase: &[u8]) -> Result<Self> {
        if path.exists() {
            return Err(SanitizerError::Vault(format!(
                "'{}' already exists; refusing to overwrite",
                path.display()
            )));
        }
        let salt = generate_salt()?;
        let key_bytes = derive_key(passphrase, &salt)?;
        let vault = Vault {
            path: path.to_path_buf(),
            key: SecureBytes::new(key_bytes.to_vec()),
            salt,
            header: VaultHeader::default(),
        };
        vault.persist()?;
        Ok(vault)
    }

    /// Open an existing vault, deriving the key from `passphrase` and
    /// verifying it via authenticated decryption of the header (a wrong
    /// passphrase fails AEAD authentication rather than silently
    /// producing garbage).
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let raw = std::fs::read(path).map_err(|e| SanitizerError::io(path, e))?;
        if raw.len() < 8 + 16 + 4 || &raw[0..8] != VAULT_MAGIC {
            return Err(SanitizerError::Vault("not a valid vault file (bad magic)".into()));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&raw[8..24]);
        let nonce_len = 12usize;
        let nonce = &raw[24..24 + nonce_len];
        let ciphertext = &raw[24 + nonce_len..];

        let key_bytes = derive_key(passphrase, &salt)?;
        let plaintext = aes256gcm_decrypt(&key_bytes, nonce, ciphertext, VAULT_MAGIC)
            .map_err(|_| SanitizerError::InvalidVaultPassword)?;
        let header: VaultHeader = serde_json::from_slice(&plaintext)?;

        Ok(Vault {
            path: path.to_path_buf(),
            key: SecureBytes::new(key_bytes.to_vec()),
            salt,
            header,
        })
    }

    fn persist(&self) -> Result<()> {
        let header_json = serde_json::to_vec(&self.header)?;
        let (nonce, ciphertext) = aes256gcm_encrypt(self.key.as_slice(), &header_json, VAULT_MAGIC)?;

        let mut out = Vec::with_capacity(8 + 16 + nonce.len() + ciphertext.len());
        out.extend_from_slice(VAULT_MAGIC);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        std::fs::write(&self.path, out).map_err(|e| SanitizerError::io(&self.path, e))?;
        Ok(())
    }

    /// Add a file's contents into the vault as an encrypted entry, keyed
    /// by a random entry ID so the on-disk vault directory listing (which
    /// is itself outside the vault, in the container file's own metadata)
    /// leaks nothing.
    pub fn add_file(&mut self, source: &Path) -> Result<String> {
        let mut f = std::fs::File::open(source).map_err(|e| SanitizerError::io(source, e))?;
        let mut data = Vec::new();
        f.read_to_end(&mut data).map_err(|e| SanitizerError::io(source, e))?;

        let sha256 = crate::crypto::hashing::sha256_hex(&data);
        let entry_id = hex::encode(secure_random_vec(16)?);
        let original_name = source
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed".to_string());

        let (nonce, ciphertext) = aes256gcm_encrypt(self.key.as_slice(), &data, entry_id.as_bytes())?;
        let entries_dir = self.entries_dir();
        std::fs::create_dir_all(&entries_dir).map_err(|e| SanitizerError::io(&entries_dir, e))?;
        let entry_path = self.entry_blob_path(&entry_id);
        let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        std::fs::write(&entry_path, blob).map_err(|e| SanitizerError::io(&entry_path, e))?;

        self.header.entries.insert(
            entry_id.clone(),
            EntryMeta {
                original_name,
                size: data.len() as u64,
                sha256,
            },
        );
        self.persist()?;
        Ok(entry_id)
    }

    pub fn extract_entry(&self, entry_id: &str, dest: &Path) -> Result<()> {
        let meta = self
            .header
            .entries
            .get(entry_id)
            .ok_or_else(|| SanitizerError::Vault(format!("no such entry: {entry_id}")))?;
        let entry_path = self.entry_blob_path(entry_id);
        let blob = std::fs::read(&entry_path).map_err(|e| SanitizerError::io(&entry_path, e))?;
        if blob.len() < 12 {
            return Err(SanitizerError::Vault("corrupt vault entry".into()));
        }
        let (nonce, ciphertext) = blob.split_at(12);
        let plaintext = aes256gcm_decrypt(self.key.as_slice(), nonce, ciphertext, entry_id.as_bytes())?;

        let actual_sha = crate::crypto::hashing::sha256_hex(&plaintext);
        if actual_sha != meta.sha256 {
            return Err(SanitizerError::Vault("integrity check failed: hash mismatch on extraction".into()));
        }

        let mut out = std::fs::File::create(dest).map_err(|e| SanitizerError::io(dest, e))?;
        out.write_all(&plaintext).map_err(|e| SanitizerError::io(dest, e))?;
        Ok(())
    }

    pub fn list_entries(&self) -> Vec<(String, String, u64)> {
        self.header
            .entries
            .iter()
            .map(|(id, meta)| (id.clone(), meta.original_name.clone(), meta.size))
            .collect()
    }

    fn entry_blob_path(&self, entry_id: &str) -> PathBuf {
        let dir = self.entries_dir();
        dir.join(format!("{entry_id}.blob"))
    }

    fn entries_dir(&self) -> PathBuf {
        let mut dir = self.path.clone();
        let file_name = format!(
            ".{}.entries",
            self.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
        );
        dir.set_file_name(file_name);
        dir
    }

    /// Securely destroy the vault: shred every entry blob, shred the
    /// container file itself, and zeroize the in-memory key. After this
    /// call the `Vault` should be dropped; `SecureBytes`'s `Drop` impl
    /// zeroizes the key regardless, this just performs on-disk cleanup
    /// explicitly and eagerly rather than waiting for scope exit.
    pub fn destroy(mut self) -> Result<()> {
        let options = ShredOptions {
            pattern: OverwritePattern::NistPurge,
            verify_passes: false,
            sanitize_filename: true,
            sync_each_pass: true,
        };

        let entries_dir = self.entries_dir();
        if entries_dir.is_dir() {
            for entry in std::fs::read_dir(&entries_dir).map_err(|e| SanitizerError::io(&entries_dir, e))? {
                let entry = entry.map_err(|e| SanitizerError::io(&entries_dir, e))?;
                let p = entry.path();
                if p.is_file() {
                    let storage = detect_storage_for_path(&p);
                    let _ = shred_file(&p, &options, &storage, None, None);
                }
            }
            let _ = std::fs::remove_dir(&entries_dir);
        }

        let storage = detect_storage_for_path(&self.path);
        let container_path = self.path.clone();
        shred_file(&container_path, &options, &storage, None, None)?;

        self.header.entries.clear();
        crate::crypto::secure_mem::secure_zero(self.key.as_mut_slice());

        Ok(())
    }
}
