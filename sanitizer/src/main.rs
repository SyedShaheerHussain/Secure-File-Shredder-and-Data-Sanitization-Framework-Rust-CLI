//! Command-line interface for the sanitizer framework.

use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use sanitizer::audit::AuditLog;
use sanitizer::crypto::hashing::sha256_hex;
use sanitizer::report::SanitizationReport;
use sanitizer::sanitize::directory::{shred_directory, DirectoryShredCallbacks};
use sanitizer::sanitize::engine::{shred_file, ShredOptions};
use sanitizer::sanitize::patterns::OverwritePattern;
use sanitizer::snapshot::scan_for_snapshots;
use sanitizer::storage::device::{detect_cloud_sync, detect_storage_for_path};
use sanitizer::storage::filesystem::detect_filesystem;
use sanitizer::vault::Vault;
use sanitizer::verify::verify_sanitization;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "sanitizer",
    version,
    about = "Production-grade secure file shredder and data sanitization framework",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Suppress non-essential output.
    #[arg(long, global = true)]
    quiet: bool,

    /// Path to the audit log (created if absent).
    #[arg(long, global = true, default_value = "sanitizer_audit.log")]
    audit_log: PathBuf,

    /// Passphrase/key material used to authenticate the audit log
    /// (HMAC key derivation). Defaults to a fixed local key if unset --
    /// for real deployments, supply via SANITIZER_AUDIT_KEY env var.
    #[arg(long, global = true, env = "SANITIZER_AUDIT_KEY")]
    audit_key: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Securely wipe a single file.
    Wipe {
        path: PathBuf,
        #[arg(long, default_value = "nist-purge")]
        pattern: String,
        #[arg(long)]
        no_verify: bool,
    },
    /// Recursively wipe every file in a directory tree.
    WipeDir {
        path: PathBuf,
        #[arg(long, default_value = "nist-purge")]
        pattern: String,
        #[arg(long)]
        threads: Option<usize>,
    },
    /// Analyze storage and filesystem characteristics for a path.
    Analyze { path: PathBuf },
    /// Run forensic verification against a file's current content.
    Verify { path: PathBuf },
    /// Generate a report from a prior sanitization run's JSON output.
    Report {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value = "human")]
        format: ReportFormat,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Verify the audit log's HMAC chain integrity instead of
        /// rendering a sanitization report.
        #[arg(long)]
        verify_audit: bool,
    },
    /// Encrypted vault operations.
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Benchmark overwrite throughput and entropy quality on this system.
    Benchmark {
        #[arg(long, default_value_t = 256)]
        size_mb: u64,
    },
    /// Attempt controlled recovery techniques against a file/image
    /// (educational forensic testing mode).
    Recover { path: PathBuf },
    /// Print storage device/filesystem info for a path.
    StorageInfo { path: PathBuf },
    /// Scan for snapshots/backups that may retain copies of data at path.
    SnapshotScan { path: PathBuf },
    /// Check if a path is inside a known cloud-sync folder.
    CloudScan { path: PathBuf },
    /// Run a basic compliance-oriented summary check (NIST 800-88 posture).
    ComplianceCheck { path: PathBuf },
}

#[derive(Subcommand)]
enum VaultAction {
    Create { path: PathBuf },
    Add { vault: PathBuf, file: PathBuf },
    List { vault: PathBuf },
    Extract { vault: PathBuf, entry_id: String, dest: PathBuf },
    Destroy { vault: PathBuf },
}

#[derive(clap::ValueEnum, Clone)]
enum ReportFormat {
    Human,
    Json,
    Csv,
}

fn prompt_password(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim_end_matches(['\n', '\r']).to_string())
}

fn audit_key_bytes(cli: &Cli) -> Vec<u8> {
    cli.audit_key
        .clone()
        .unwrap_or_else(|| "sanitizer-default-local-audit-key-change-me".to_string())
        .into_bytes()
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let cancel = Arc::new(AtomicBool::new(false));
    {
        let cancel = cancel.clone();
        ctrlc::set_handler(move || {
            eprintln!("\n{}", "Cancellation requested; finishing current write chunk...".yellow());
            cancel.store(true, Ordering::Relaxed);
        })
        .ok();
    }

    let key_bytes = audit_key_bytes(&cli);
    let mut audit = AuditLog::open(&cli.audit_log, &key_bytes, false)
        .map_err(|e| anyhow::anyhow!("failed to open audit log: {e}"))?;

    match cli.command {
        Commands::Wipe { path, pattern, no_verify } => {
            let pattern = OverwritePattern::from_str(&pattern).map_err(|e| anyhow::anyhow!(e))?;
            let storage = detect_storage_for_path(&path);
            let fs_info = detect_filesystem(&path);

            if !cli.quiet {
                println!("{} {}", "Target:".bold(), path.display());
                println!("  Storage: {}", storage.kind);
                println!("  Filesystem: {}", fs_info.kind);
                for note in storage.notes.iter().chain(fs_info.notes.iter()) {
                    println!("  {} {}", "note:".dimmed(), note);
                }
                if let Some(cloud) = detect_cloud_sync(&path) {
                    println!(
                        "  {} File synced to cloud ({cloud}). Local wipe won't remove cloud copies.",
                        "WARNING:".red().bold()
                    );
                }
            }

            let options = ShredOptions {
                pattern,
                verify_passes: !no_verify,
                sanitize_filename: true,
                sync_each_pass: true,
            };

            let pb = if !cli.quiet {
                let bar = ProgressBar::new(100);
                bar.set_style(
                    ProgressStyle::with_template("{spinner:.green} [{bar:40.cyan/blue}] {percent}% {msg}")
                        .unwrap()
                        .progress_chars("=>-"),
                );
                Some(bar)
            } else {
                None
            };

            let file_size = std::fs::metadata(&path)?.len().max(1);
            let progress_cb = |done: u64, pass: u32, total_passes: u32| {
                if let Some(bar) = &pb {
                    let pct = ((done as f64 / file_size as f64) * 100.0 / total_passes as f64
                        + (pass as f64 / total_passes as f64) * 100.0)
                        .min(100.0);
                    bar.set_position(pct as u64);
                    bar.set_message(format!("pass {}/{}", pass + 1, total_passes));
                }
            };

            let outcome = shred_file(&path, &options, &storage, Some(cancel.clone()), Some(&progress_cb))
                .map_err(|e| anyhow::anyhow!("wipe failed: {e}"))?;

            if let Some(bar) = pb {
                bar.finish_with_message("done");
            }

            audit.record(
                "wipe",
                &outcome.path.to_string_lossy(),
                serde_json::to_value(&outcome)?,
            )?;

            if !cli.quiet {
                println!("{} {} bytes wiped in {} pass(es), {}ms", "OK:".green().bold(), outcome.bytes_wiped, outcome.passes_completed, outcome.duration_ms);
                for w in &outcome.warnings {
                    println!("  {} {}", "WARNING:".yellow().bold(), w);
                }
            }
        }

        Commands::WipeDir { path, pattern, threads } => {
            let pattern = OverwritePattern::from_str(&pattern).map_err(|e| anyhow::anyhow!(e))?;
            let options = ShredOptions {
                pattern,
                verify_passes: true,
                sanitize_filename: true,
                sync_each_pass: true,
            };

            let pb = if !cli.quiet {
                Some(ProgressBar::new(0))
            } else {
                None
            };
            let pb_clone = pb.clone();

            let callbacks = DirectoryShredCallbacks {
                on_file_done: Some(Box::new(move |done, total| {
                    if let Some(bar) = &pb_clone {
                        bar.set_length(total as u64);
                        bar.set_position(done as u64);
                    }
                })),
            };

            let summary = shred_directory(&path, &options, threads, Some(cancel.clone()), callbacks)
                .map_err(|e| anyhow::anyhow!("directory wipe failed: {e}"))?;

            if let Some(bar) = pb {
                bar.finish_with_message("done");
            }

            audit.record(
                "wipe-dir",
                &path.to_string_lossy(),
                serde_json::json!({
                    "files_processed": summary.files_processed,
                    "files_failed": summary.files_failed,
                    "bytes_wiped": summary.bytes_wiped
                }),
            )?;

            println!(
                "{} {} files wiped ({} bytes), {} failed",
                "OK:".green().bold(),
                summary.files_processed,
                summary.bytes_wiped,
                summary.files_failed
            );
            for (p, err) in &summary.errors {
                println!("  {} {}: {}", "ERROR:".red().bold(), p.display(), err);
            }
        }

        Commands::Analyze { path } => {
            let storage = detect_storage_for_path(&path);
            let fs_info = detect_filesystem(&path);
            println!("{}", format!("Storage analysis for {}", path.display()).bold());
            println!("  Storage kind: {}", storage.kind);
            println!("  Device: {}", storage.device_name.as_deref().unwrap_or("unknown"));
            println!("  TRIM supported: {:?}", storage.trim_supported);
            println!("  Overwrite reliable: {}", storage.overwrite_is_reliable());
            println!("  Filesystem: {}", fs_info.kind);
            println!("  Journaling: {}  COW: {}  Dedup: {}  Compression: {}  Snapshots: {}",
                fs_info.is_journaling, fs_info.is_copy_on_write, fs_info.supports_dedup, fs_info.supports_compression, fs_info.supports_snapshots);
            for note in storage.notes.iter().chain(fs_info.notes.iter()) {
                println!("  note: {note}");
            }
        }

        Commands::Verify { path } => {
            let report = verify_sanitization(&path).map_err(|e| anyhow::anyhow!("verification failed: {e}"))?;
            println!("{}", format!("Forensic verification: {}", path.display()).bold());
            println!("  Entropy: {:.3} bits/byte", report.entropy);
            println!("  Signature hits: {:?}", report.signature_hits);
            println!("  ASCII strings found: {}", report.ascii_strings_found);
            println!("  Recovery confidence: {} (score {:.2})", report.recovery_confidence, report.confidence_score);
            println!("  {}", report.summary);
        }

        Commands::Report { input, format, output, verify_audit } => {
            if verify_audit {
                let count = AuditLog::verify_file(&input, &key_bytes, false)
                    .map_err(|e| anyhow::anyhow!("audit log verification failed: {e}"))?;
                println!("{} audit log verified: {} entries, chain intact", "OK:".green().bold(), count);
                return Ok(());
            }

            let json = std::fs::read_to_string(&input)?;
            let report: SanitizationReport = serde_json::from_str(&json)?;
            let rendered = match format {
                ReportFormat::Human => report.human_readable(),
                ReportFormat::Json => report.to_json_pretty()?,
                ReportFormat::Csv => {
                    let out_path = output.clone().unwrap_or_else(|| PathBuf::from("report.csv"));
                    report.write_csv(&out_path)?;
                    println!("{} CSV report written to {}", "OK:".green().bold(), out_path.display());
                    return Ok(());
                }
            };

            match output {
                Some(out_path) => {
                    std::fs::write(&out_path, rendered)?;
                    println!("{} report written to {}", "OK:".green().bold(), out_path.display());
                }
                None => println!("{rendered}"),
            }
        }

        Commands::Vault { action } => match action {
            VaultAction::Create { path } => {
                let pw = prompt_password("Vault passphrase")?;
                Vault::create(&path, pw.as_bytes()).map_err(|e| anyhow::anyhow!("vault create failed: {e}"))?;
                audit.record("vault-create", &path.to_string_lossy(), serde_json::json!({}))?;
                println!("{} vault created at {}", "OK:".green().bold(), path.display());
            }
            VaultAction::Add { vault, file } => {
                let pw = prompt_password("Vault passphrase")?;
                let mut v = Vault::open(&vault, pw.as_bytes()).map_err(|e| anyhow::anyhow!("vault open failed: {e}"))?;
                let entry_id = v.add_file(&file).map_err(|e| anyhow::anyhow!("vault add failed: {e}"))?;
                audit.record("vault-add", &vault.to_string_lossy(), serde_json::json!({"entry_id": entry_id, "sha256": sha256_hex(&std::fs::read(&file)?)}))?;
                println!("{} added as entry {}", "OK:".green().bold(), entry_id);
            }
            VaultAction::List { vault } => {
                let pw = prompt_password("Vault passphrase")?;
                let v = Vault::open(&vault, pw.as_bytes()).map_err(|e| anyhow::anyhow!("vault open failed: {e}"))?;
                for (id, name, size) in v.list_entries() {
                    println!("{id}  {name}  {size} bytes");
                }
            }
            VaultAction::Extract { vault, entry_id, dest } => {
                let pw = prompt_password("Vault passphrase")?;
                let v = Vault::open(&vault, pw.as_bytes()).map_err(|e| anyhow::anyhow!("vault open failed: {e}"))?;
                v.extract_entry(&entry_id, &dest).map_err(|e| anyhow::anyhow!("extract failed: {e}"))?;
                println!("{} extracted to {}", "OK:".green().bold(), dest.display());
            }
            VaultAction::Destroy { vault } => {
                let pw = prompt_password("Vault passphrase (confirm destroy)")?;
                let v = Vault::open(&vault, pw.as_bytes()).map_err(|e| anyhow::anyhow!("vault open failed: {e}"))?;
                let path_str = vault.to_string_lossy().to_string();
                v.destroy().map_err(|e| anyhow::anyhow!("vault destroy failed: {e}"))?;
                audit.record("vault-destroy", &path_str, serde_json::json!({}))?;
                println!("{} vault destroyed", "OK:".green().bold());
            }
        },

        Commands::Benchmark { size_mb } => {
            run_benchmark(size_mb)?;
        }

        Commands::Recover { path } => {
            let report = verify_sanitization(&path).map_err(|e| anyhow::anyhow!("recovery test failed: {e}"))?;
            println!("{}", "=== Anti-Recovery Research Mode ===".bold());
            println!("Signature scan: {:?}", report.signature_hits);
            println!("Carving-style string extraction (sample): {:?}", report.sample_strings);
            println!("Entropy measurement: {:.3} bits/byte", report.entropy);
            println!("Estimated recovery confidence: {} ({:.2})", report.recovery_confidence, report.confidence_score);
            println!("{}", report.summary);
        }

        Commands::StorageInfo { path } => {
            let storage = detect_storage_for_path(&path);
            println!("{storage:#?}");
        }

        Commands::SnapshotScan { path } => {
            let report = scan_for_snapshots(&path);
            if report.has_risk() {
                println!("{}", "Snapshot/backup risk detected:".yellow().bold());
                for f in &report.findings {
                    println!("  [{}] {}", f.mechanism, f.description);
                    println!("    remediation: {}", f.remediation);
                }
            } else {
                println!("{} no snapshot/backup mechanisms detected for this path", "OK:".green().bold());
            }
        }

        Commands::CloudScan { path } => {
            match detect_cloud_sync(&path) {
                Some(provider) => println!(
                    "{} File synced to cloud ({provider}).\nLocal wipe won't remove cloud copies.",
                    "WARNING:".red().bold()
                ),
                None => println!("{} no cloud-sync markers detected in this path", "OK:".green().bold()),
            }
        }

        Commands::ComplianceCheck { path } => {
            let storage = detect_storage_for_path(&path);
            let fs_info = detect_filesystem(&path);
            let snapshot_report = scan_for_snapshots(&path);
            let cloud = detect_cloud_sync(&path);

            println!("{}", "=== NIST SP 800-88 Posture Check ===".bold());
            println!("Storage: {} -> overwrite reliable: {}", storage.kind, storage.overwrite_is_reliable());
            if storage.recommend_crypto_erase() {
                println!("  Recommendation: use Purge-level method (crypto-erase or native Sanitize command), not Clear-level overwrite alone.");
            }
            println!("Filesystem: {} -> COW: {}, snapshots supported: {}", fs_info.kind, fs_info.is_copy_on_write, fs_info.supports_snapshots);
            if snapshot_report.has_risk() {
                println!("Snapshots/backups detected: {} finding(s) -- see `snapshot-scan` for details.", snapshot_report.findings.len());
            }
            if let Some(c) = &cloud {
                println!("Cloud sync: {c} detected -- remote copies require separate purge action.");
            }
            println!("\nOverall: {}", if storage.overwrite_is_reliable() && !snapshot_report.has_risk() && cloud.is_none() {
                "LOW RISK - standard overwrite sanitization should be effective".green().to_string()
            } else {
                "ELEVATED RISK - review recommendations above before relying on overwrite alone".yellow().to_string()
            });
        }
    }

    Ok(())
}

fn run_benchmark(size_mb: u64) -> anyhow::Result<()> {
    use sanitizer::crypto::rng::{secure_random_vec, shannon_entropy};
    use std::time::Instant;

    println!("{}", format!("Benchmarking {size_mb} MiB of secure random generation + write throughput...").bold());

    let bytes = (size_mb * 1024 * 1024) as usize;
    let start = Instant::now();
    let data = secure_random_vec(bytes.min(64 * 1024 * 1024))?; // cap single-buffer gen for benchmark sanity
    let gen_elapsed = start.elapsed();
    let entropy = shannon_entropy(&data);

    let tmp_path = std::env::temp_dir().join(format!("sanitizer_bench_{}.tmp", std::process::id()));
    let write_start = Instant::now();
    {
        let mut f = std::fs::File::create(&tmp_path)?;
        let mut remaining = bytes;
        while remaining > 0 {
            let chunk = remaining.min(data.len());
            f.write_all(&data[..chunk])?;
            remaining -= chunk;
        }
        f.sync_all()?;
    }
    let write_elapsed = write_start.elapsed();
    let _ = std::fs::remove_file(&tmp_path);

    let gen_mb_s = (bytes as f64 / (1024.0 * 1024.0)) / gen_elapsed.as_secs_f64().max(1e-9);
    let write_mb_s = (bytes as f64 / (1024.0 * 1024.0)) / write_elapsed.as_secs_f64().max(1e-9);

    println!("  CSPRNG generation: {:.1} MiB/s (sample entropy {:.3} bits/byte)", gen_mb_s, entropy);
    println!("  Disk write throughput: {:.1} MiB/s", write_mb_s);
    println!("  CPU threads available: {}", num_cpus::get());

    Ok(())
}
