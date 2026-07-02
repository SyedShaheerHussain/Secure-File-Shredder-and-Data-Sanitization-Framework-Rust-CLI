//! Recursive directory shredding using a rayon thread pool for
//! high-throughput parallel wiping of large trees.

use crate::error::{Result, SanitizerError};
use crate::sanitize::engine::{shred_file, CancelFlag, ShredOptions, ShredOutcome};
use crate::storage::device::detect_storage_for_path;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct DirectoryShredSummary {
    pub files_processed: usize,
    pub files_failed: usize,
    pub bytes_wiped: u64,
    pub outcomes: Vec<ShredOutcome>,
    pub errors: Vec<(PathBuf, String)>,
}

pub struct DirectoryShredCallbacks<'a> {
    /// Called after each file completes (successfully or not) with
    /// (files_done, files_total).
    pub on_file_done: Option<Box<dyn Fn(usize, usize) + Send + Sync + 'a>>,
}

/// Recursively shred every regular file under `root` using `options`.
/// Directories are walked first (single-threaded, cheap) to build a file
/// list and enable accurate progress totals, then files are wiped in
/// parallel across a rayon thread pool sized to the available CPUs.
/// Directory entries themselves are removed afterward, deepest-first.
pub fn shred_directory(
    root: &Path,
    options: &ShredOptions,
    thread_count: Option<usize>,
    cancel: Option<CancelFlag>,
    callbacks: DirectoryShredCallbacks,
) -> Result<DirectoryShredSummary> {
    if !root.is_dir() {
        return Err(SanitizerError::Config(format!(
            "'{}' is not a directory",
            root.display()
        )));
    }

    let files: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();

    let total = files.len();
    let done_counter = Arc::new(AtomicUsize::new(0));
    let summary = Arc::new(Mutex::new(DirectoryShredSummary::default()));

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count.unwrap_or_else(num_cpus::get))
        .build()
        .map_err(|e| SanitizerError::Config(format!("failed to build thread pool: {e}")))?;

    let on_file_done = callbacks.on_file_done;

    pool.install(|| {
        files.par_iter().for_each(|file_path| {
            if cancel.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                return;
            }
            let storage = detect_storage_for_path(file_path);
            let result = shred_file(file_path, options, &storage, cancel.clone(), None);

            let mut summary_guard = summary.lock().unwrap();
            match result {
                Ok(outcome) => {
                    summary_guard.files_processed += 1;
                    summary_guard.bytes_wiped += outcome.bytes_wiped;
                    summary_guard.outcomes.push(outcome);
                }
                Err(e) => {
                    summary_guard.files_failed += 1;
                    summary_guard.errors.push((file_path.clone(), e.to_string()));
                }
            }
            drop(summary_guard);

            let done = done_counter.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(cb) = &on_file_done {
                cb(done, total);
            }
        });
    });

    // Remove now-empty directories, deepest first, so parent directories
    // become empty in turn.
    let mut dirs: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
        .map(|e| e.path().to_path_buf())
        .collect();
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for dir in dirs {
        let _ = std::fs::remove_dir(&dir); // best-effort; non-empty dirs (failed files) are left in place
    }

    Arc::try_unwrap(summary)
        .map(|m| m.into_inner().unwrap())
        .map_err(|_| SanitizerError::Config("internal: summary still shared after join".into()))
}
