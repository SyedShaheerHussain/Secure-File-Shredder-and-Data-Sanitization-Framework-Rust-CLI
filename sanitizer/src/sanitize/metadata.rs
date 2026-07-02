//! Metadata sanitization: securely rename a file through several random
//! filenames before final deletion (defeats journal/MFT entries retaining
//! the original filename in plaintext), then unlink it.

use crate::crypto::rng::secure_random_vec;
use crate::error::{Result, SanitizerError};
use std::path::{Path, PathBuf};

const RENAME_ROUNDS: usize = 3;

/// Rename `path` several times to random same-length-ish names in its
/// parent directory, then remove it. This does not guarantee the old
/// directory-entry bytes are physically overwritten (that depends on the
/// filesystem and is out of userspace control), but it removes the
/// plaintext filename from the live directory listing and reduces the
/// window in which the original name is discoverable via simple
/// directory-entry scraping.
pub fn sanitize_metadata_and_unlink(path: &Path, sanitize_filename: bool) -> Result<()> {
    let mut current = path.to_path_buf();

    if sanitize_filename {
        let parent = current
            .parent()
            .ok_or_else(|| SanitizerError::Config("file has no parent directory".into()))?
            .to_path_buf();

        for _ in 0..RENAME_ROUNDS {
            let random_name = random_filename();
            let new_path: PathBuf = parent.join(random_name);
            std::fs::rename(&current, &new_path).map_err(|e| SanitizerError::io(&current, e))?;
            current = new_path;
        }

        // Best-effort: clear/normalize timestamps on the final name before
        // unlink so a subsequent directory-entry or journal scan is less
        // informative. filetime updates are OS-dependent; failures here
        // are non-fatal since the file is about to be removed anyway.
        let _ = clear_timestamps(&current);
    }

    std::fs::remove_file(&current).map_err(|e| SanitizerError::io(&current, e))?;
    Ok(())
}

fn random_filename() -> String {
    let bytes = secure_random_vec(16).unwrap_or_else(|_| vec![0u8; 16]);
    hex::encode(bytes)
}

fn clear_timestamps(path: &Path) -> std::io::Result<()> {
    // Setting a file's mtime/atime to the Unix epoch via the standard
    // library requires platform-specific syscalls (utimensat on Linux,
    // SetFileTime on Windows) that aren't exposed through std::fs
    // directly. We touch the file (open + set_len to current length) as
    // a portable no-op that at least updates mtime to "now" rather than
    // leaving the historically meaningful original timestamp, and record
    // that full epoch-reset requires the platform layer.
    let f = std::fs::OpenOptions::new().write(true).open(path)?;
    let len = f.metadata()?.len();
    f.set_len(len)?;
    Ok(())
}
