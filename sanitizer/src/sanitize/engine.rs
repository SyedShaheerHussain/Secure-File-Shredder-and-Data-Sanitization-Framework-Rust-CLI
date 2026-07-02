//! Core single-file secure overwrite + delete engine.

use crate::error::{Result, SanitizerError};
use crate::sanitize::metadata::sanitize_metadata_and_unlink;
use crate::sanitize::patterns::OverwritePattern;
use crate::storage::device::StorageInfo;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB write chunks

#[derive(Debug, Clone)]
pub struct ShredOptions {
    pub pattern: OverwritePattern,
    pub verify_passes: bool,
    pub sanitize_filename: bool,
    pub sync_each_pass: bool,
}

impl Default for ShredOptions {
    fn default() -> Self {
        Self {
            pattern: OverwritePattern::NistPurge,
            verify_passes: true,
            sanitize_filename: true,
            sync_each_pass: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShredOutcome {
    pub path: PathBuf,
    pub bytes_wiped: u64,
    pub passes_completed: u32,
    pub pattern: String,
    pub duration_ms: u128,
    pub verification_entropy: Option<f64>,
    pub storage_kind: String,
    pub overwrite_reliable: bool,
    pub warnings: Vec<String>,
}

/// Shared cancellation flag; a Ctrl-C handler or CLI cancel command sets
/// this to request that in-progress and queued shred operations stop
/// after completing their current write chunk, leaving files in a
/// consistent (already-overwritten-so-far) state rather than aborting
/// mid-write.
pub type CancelFlag = Arc<AtomicBool>;

/// Optional progress sink: called with (bytes_done_this_call, pass_index,
/// total_passes) as writing proceeds, for CLI progress bars.
pub type ProgressCallback<'a> = dyn Fn(u64, u32, u32) + Send + Sync + 'a;

pub fn shred_file(
    path: &Path,
    options: &ShredOptions,
    storage: &StorageInfo,
    cancel: Option<CancelFlag>,
    progress: Option<&ProgressCallback>,
) -> Result<ShredOutcome> {
    let start = Instant::now();
    let metadata = std::fs::metadata(path).map_err(|e| SanitizerError::io(path, e))?;
    if !metadata.is_file() {
        return Err(SanitizerError::Config(format!(
            "'{}' is not a regular file",
            path.display()
        )));
    }
    let file_len = metadata.len();
    let total_passes = options.pattern.passes();
    let mut warnings = Vec::new();

    if !storage.overwrite_is_reliable() {
        warnings.push(format!(
            "Storage class '{}' does not guarantee overwrite reliability at the physical layer; consider crypto-erase or a native Sanitize/Secure Erase command in addition to this overwrite.",
            storage.kind
        ));
    }
    warnings.extend(storage.notes.iter().cloned());

    let bytes_wiped = Arc::new(AtomicU64::new(0));
    let mut passes_completed = 0u32;

    'passes: for pass in 0..total_passes {
        if cancel.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
            return Err(SanitizerError::Cancelled);
        }

        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| SanitizerError::io(path, e))?;
        file.seek(SeekFrom::Start(0)).map_err(|e| SanitizerError::io(path, e))?;

        let mut remaining = file_len;
        let mut buf = vec![0u8; CHUNK_SIZE.min(file_len.max(1) as usize)];

        while remaining > 0 {
            if cancel.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                break 'passes;
            }
            let this_chunk = remaining.min(buf.len() as u64) as usize;
            options.pattern.fill_pass(&mut buf[..this_chunk], pass)?;
            file.write_all(&buf[..this_chunk]).map_err(|e| SanitizerError::io(path, e))?;
            remaining -= this_chunk as u64;
            let done = bytes_wiped.fetch_add(this_chunk as u64, Ordering::Relaxed) + this_chunk as u64;
            if let Some(cb) = progress {
                cb(done, pass, total_passes);
            }
        }

        if options.sync_each_pass {
            file.sync_all().map_err(|e| SanitizerError::io(path, e))?;
        }
        passes_completed += 1;
    }

    // Post-pass verification: re-read the file and measure entropy of the
    // final overwrite pass to detect anomalies (e.g. a filesystem that
    // silently redirected writes via copy-on-write, leaving low-entropy
    // remnants where the original data logically was).
    let verification_entropy = if options.verify_passes && passes_completed == total_passes {
        std::fs::read(path).ok().map(|data| crate::crypto::rng::shannon_entropy(&data))
    } else {
        None
    };

    if let Some(entropy) = verification_entropy {
        let last_pass_is_random = matches!(
            options.pattern,
            OverwritePattern::SingleRandom
                | OverwritePattern::MultiRandom(_)
                | OverwritePattern::DodThreePass
                | OverwritePattern::NistPurge
        );
        if last_pass_is_random && entropy < 7.0 && file_len > 4096 {
            warnings.push(format!(
                "Post-overwrite entropy measured at {entropy:.2} bits/byte, lower than expected for a random pass; the filesystem may have redirected the write (copy-on-write) rather than overwriting in place."
            ));
        }
    }

    let final_bytes = bytes_wiped.load(Ordering::Relaxed);

    if passes_completed == total_passes {
        sanitize_metadata_and_unlink(path, options.sanitize_filename)?;
    } else {
        return Err(SanitizerError::Cancelled);
    }

    Ok(ShredOutcome {
        path: path.to_path_buf(),
        bytes_wiped: final_bytes,
        passes_completed,
        pattern: options.pattern.name(),
        duration_ms: start.elapsed().as_millis(),
        verification_entropy,
        storage_kind: storage.kind.to_string(),
        overwrite_reliable: storage.overwrite_is_reliable(),
        warnings,
    })
}
