//! Reporting engine: aggregates sanitization outcomes, verification
//! results, storage/filesystem analysis, and snapshot/cloud-sync warnings
//! into human-readable, JSON, and CSV report formats.

use crate::sanitize::engine::ShredOutcome;
use crate::snapshot::SnapshotScanReport;
use crate::verify::VerificationReport;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationReport {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub tool_version: String,
    pub outcomes: Vec<ShredOutcome>,
    pub verifications: Vec<VerificationReport>,
    pub snapshot_findings: Vec<SnapshotScanReport>,
    pub total_files: usize,
    pub total_bytes_wiped: u64,
    pub total_warnings: usize,
}

impl SanitizationReport {
    pub fn new(outcomes: Vec<ShredOutcome>, verifications: Vec<VerificationReport>, snapshot_findings: Vec<SnapshotScanReport>) -> Self {
        let total_files = outcomes.len();
        let total_bytes_wiped = outcomes.iter().map(|o| o.bytes_wiped).sum();
        let total_warnings = outcomes.iter().map(|o| o.warnings.len()).sum();
        SanitizationReport {
            report_id: uuid::Uuid::new_v4().to_string(),
            generated_at: Utc::now(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            outcomes,
            verifications,
            snapshot_findings,
            total_files,
            total_bytes_wiped,
            total_warnings,
        }
    }

    pub fn to_json_pretty(&self) -> crate::error::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn write_json(&self, path: &Path) -> crate::error::Result<()> {
        let json = self.to_json_pretty()?;
        std::fs::write(path, json).map_err(|e| crate::error::SanitizerError::io(path, e))
    }

    pub fn write_csv(&self, path: &Path) -> crate::error::Result<()> {
        let mut file = std::fs::File::create(path).map_err(|e| crate::error::SanitizerError::io(path, e))?;
        writeln!(
            file,
            "path,bytes_wiped,passes_completed,pattern,duration_ms,verification_entropy,storage_kind,overwrite_reliable,warning_count"
        )
        .map_err(|e| crate::error::SanitizerError::io(path, e))?;

        for outcome in &self.outcomes {
            writeln!(
                file,
                "{},{},{},{},{},{},{},{},{}",
                csv_escape(&outcome.path.to_string_lossy()),
                outcome.bytes_wiped,
                outcome.passes_completed,
                outcome.pattern,
                outcome.duration_ms,
                outcome.verification_entropy.map(|e| format!("{e:.3}")).unwrap_or_default(),
                csv_escape(&outcome.storage_kind),
                outcome.overwrite_reliable,
                outcome.warnings.len(),
            )
            .map_err(|e| crate::error::SanitizerError::io(path, e))?;
        }
        Ok(())
    }

    pub fn human_readable(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "=== Sanitization Report {} ===\nGenerated: {}\nTool version: {}\n\n",
            self.report_id,
            self.generated_at.to_rfc3339(),
            self.tool_version
        ));
        out.push_str(&format!(
            "Files processed: {}\nTotal bytes wiped: {} ({:.2} MiB)\nWarnings raised: {}\n\n",
            self.total_files,
            self.total_bytes_wiped,
            self.total_bytes_wiped as f64 / (1024.0 * 1024.0),
            self.total_warnings
        ));

        for outcome in &self.outcomes {
            out.push_str(&format!(
                "- {}\n    pattern={} passes={} bytes={} duration={}ms storage={} reliable_overwrite={}\n",
                outcome.path.display(),
                outcome.pattern,
                outcome.passes_completed,
                outcome.bytes_wiped,
                outcome.duration_ms,
                outcome.storage_kind,
                outcome.overwrite_reliable
            ));
            if let Some(e) = outcome.verification_entropy {
                out.push_str(&format!("    post-overwrite entropy: {e:.2} bits/byte\n"));
            }
            for w in &outcome.warnings {
                out.push_str(&format!("    WARNING: {w}\n"));
            }
        }

        if !self.verifications.is_empty() {
            out.push_str("\n--- Forensic Verification ---\n");
            for v in &self.verifications {
                out.push_str(&format!(
                    "- {} confidence={} score={:.2} entropy={:.2} signatures={:?}\n",
                    v.path.display(),
                    v.recovery_confidence,
                    v.confidence_score,
                    v.entropy,
                    v.signature_hits
                ));
            }
        }

        let any_snapshot_risk = self.snapshot_findings.iter().any(|s| s.has_risk());
        if any_snapshot_risk {
            out.push_str("\n--- Snapshot / Backup Risk ---\n");
            for scan in &self.snapshot_findings {
                for finding in &scan.findings {
                    out.push_str(&format!("- [{}] {}\n    remediation: {}\n", finding.mechanism, finding.description, finding.remediation));
                }
            }
        }

        out
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
