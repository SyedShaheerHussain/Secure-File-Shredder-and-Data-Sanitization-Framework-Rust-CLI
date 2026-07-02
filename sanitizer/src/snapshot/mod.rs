//! Snapshot and backup-mechanism awareness: detects Btrfs/ZFS/LVM
//! snapshots, Windows Volume Shadow Copies, and common backup targets
//! that may retain copies of data outside the primary file location.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFinding {
    pub mechanism: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SnapshotScanReport {
    pub findings: Vec<SnapshotFinding>,
}

impl SnapshotScanReport {
    pub fn has_risk(&self) -> bool {
        !self.findings.is_empty()
    }
}

pub fn scan_for_snapshots(path: &Path) -> SnapshotScanReport {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        findings.extend(linux::scan(path));
    }
    #[cfg(target_os = "windows")]
    {
        findings.extend(windows::scan(path));
    }

    findings.extend(generic_backup_dir_scan(path));

    SnapshotScanReport { findings }
}

/// Heuristic scan for common backup-tool target directories/markers
/// (rsnapshot, Time Machine-style, borg, restic repos) near the target
/// path -- platform-independent, name/marker based.
fn generic_backup_dir_scan(path: &Path) -> Vec<SnapshotFinding> {
    let mut findings = Vec::new();
    let path_str = path.to_string_lossy().to_lowercase();
    let markers: &[(&str, &str)] = &[
        (".git", "Git repository history may retain committed versions of the file."),
        ("time machine", "Apple Time Machine backup target may retain historical copies."),
        ("backuppc", "BackupPC repository may retain historical copies."),
        ("borgbackup", "Borg backup repository may retain historical copies."),
        (".restic", "Restic backup repository may retain historical copies."),
        ("veeam", "Veeam backup repository may retain historical copies."),
    ];
    for (marker, desc) in markers {
        if path_str.contains(marker) {
            findings.push(SnapshotFinding {
                mechanism: (*marker).to_string(),
                description: (*desc).to_string(),
                remediation: "Locate and separately purge the backup repository's retained copies, subject to its own retention/immutability policy.".to_string(),
            });
        }
    }
    findings
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::Command;

    pub fn scan(path: &Path) -> Vec<SnapshotFinding> {
        let mut findings = Vec::new();
        findings.extend(scan_btrfs(path));
        findings.extend(scan_lvm());
        findings.extend(scan_zfs());
        findings
    }

    fn scan_btrfs(path: &Path) -> Vec<SnapshotFinding> {
        // `btrfs subvolume list -s <path>` lists snapshots on the
        // containing filesystem; absence of the `btrfs` binary or a
        // non-btrfs filesystem is not an error, just no findings.
        let mount_point = path.to_string_lossy().to_string();
        match Command::new("btrfs")
            .args(["subvolume", "list", "-s", &mount_point])
            .output()
        {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let count = stdout.lines().filter(|l| !l.trim().is_empty()).count();
                if count > 0 {
                    vec![SnapshotFinding {
                        mechanism: "Btrfs snapshot".into(),
                        description: format!("{count} Btrfs snapshot(s) detected on this filesystem; deleted/overwritten files may remain accessible via a snapshot taken before sanitization."),
                        remediation: "Identify and delete relevant snapshots with `btrfs subvolume delete`, respecting any retention requirements, then re-run verification.".into(),
                    }]
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }

    fn scan_lvm() -> Vec<SnapshotFinding> {
        match Command::new("lvs")
            .args(["--noheadings", "-o", "lv_name,origin"])
            .output()
        {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let snapshot_count = stdout
                    .lines()
                    .filter(|l| l.split_whitespace().nth(1).is_some())
                    .count();
                if snapshot_count > 0 {
                    vec![SnapshotFinding {
                        mechanism: "LVM snapshot".into(),
                        description: format!("{snapshot_count} LVM snapshot volume(s) detected on this system; they may retain pre-sanitization data blocks."),
                        remediation: "Review `lvs` output and remove stale snapshots with `lvremove` once no longer needed for recovery purposes.".into(),
                    }]
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }

    fn scan_zfs() -> Vec<SnapshotFinding> {
        match Command::new("zfs").args(["list", "-t", "snapshot", "-H"]).output() {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let count = stdout.lines().filter(|l| !l.trim().is_empty()).count();
                if count > 0 {
                    vec![SnapshotFinding {
                        mechanism: "ZFS snapshot".into(),
                        description: format!("{count} ZFS snapshot(s) detected; sanitized data may remain accessible via `zfs rollback` or snapshot mounts."),
                        remediation: "Destroy relevant snapshots with `zfs destroy pool/dataset@snapshot` once retention policy allows.".into(),
                    }]
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::process::Command;

    pub fn scan(_path: &Path) -> Vec<SnapshotFinding> {
        let mut findings = Vec::new();

        // `vssadmin list shadows` enumerates Volume Shadow Copies; requires
        // administrative privileges to run successfully.
        if let Ok(output) = Command::new("vssadmin").args(["list", "shadows"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let count = stdout.matches("Shadow Copy ID").count();
            if count > 0 {
                findings.push(SnapshotFinding {
                    mechanism: "Volume Shadow Copy (VSS)".into(),
                    description: format!("{count} Volume Shadow Copy snapshot(s) detected; File History and System Restore may also depend on these, and they can retain pre-sanitization file versions."),
                    remediation: "Review and delete relevant shadow copies with `vssadmin delete shadows` (administrative privileges required), respecting System Restore needs.".into(),
                });
            }
        }

        findings.push(SnapshotFinding {
            mechanism: "Windows File History / System Restore".into(),
            description: "If File History or System Restore is enabled on this volume, historical file versions may be retained independently of the live filesystem.".into(),
            remediation: "Check File History settings and System Protection configuration; disable or purge history for the relevant drive if full sanitization is required.".into(),
        });

        findings
    }
}
