//! Filesystem type identification and characteristics relevant to secure
//! deletion (journaling, copy-on-write, dedup, compression, snapshotting).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilesystemKind {
    Ntfs,
    Fat32,
    ExFat,
    ReFs,
    Ext4,
    Xfs,
    Btrfs,
    Zfs,
    F2fs,
    Apfs,
    Tmpfs,
    Overlay,
    Unknown,
}

impl std::fmt::Display for FilesystemKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemInfo {
    pub path: PathBuf,
    pub kind: FilesystemKind,
    pub is_journaling: bool,
    pub is_copy_on_write: bool,
    pub supports_dedup: bool,
    pub supports_compression: bool,
    pub supports_snapshots: bool,
    pub notes: Vec<String>,
}

impl FilesystemInfo {
    fn for_kind(path: &Path, kind: FilesystemKind) -> Self {
        let (journaling, cow, dedup, compression, snapshots, mut notes) = match kind {
            FilesystemKind::Ntfs => (true, false, false, true, true, vec![
                "NTFS journal ($LogFile) and Volume Shadow Copy Service may retain recoverable data outside the target file's allocated clusters.".to_string()
            ]),
            FilesystemKind::ReFs => (true, true, true, false, true, vec![
                "ReFS is copy-on-write with block cloning/dedup; overwriting a file's logical content may not overwrite the original physical blocks.".to_string()
            ]),
            FilesystemKind::Fat32 | FilesystemKind::ExFat => (false, false, false, false, false, vec![
                "No journaling or COW; direct overwrite is comparatively reliable on the underlying medium, subject to storage-class caveats.".to_string()
            ]),
            FilesystemKind::Ext4 => (true, false, false, false, false, vec![
                "ext4 journal (data=ordered/journal mode) may retain copies of recently written metadata or, in data-journaling mode, file content.".to_string()
            ]),
            FilesystemKind::Xfs => (true, false, false, false, false, vec![
                "XFS metadata journal may retain metadata remnants; data blocks are generally overwritten in place.".to_string()
            ]),
            FilesystemKind::Btrfs => (false, true, true, true, true, vec![
                "Btrfs is copy-on-write with native snapshot support; deleting/overwriting a file does not affect blocks retained by existing snapshots.".to_string()
            ]),
            FilesystemKind::Zfs => (true, true, true, true, true, vec![
                "ZFS is copy-on-write with snapshots, dedup, and compression; overwritten data may remain accessible via existing snapshots or the dedup table.".to_string()
            ]),
            FilesystemKind::F2fs => (true, true, false, true, false, vec![
                "F2FS is a log-structured, flash-friendly filesystem with its own wear-leveling; overwrite semantics resemble SSD/NVMe caveats.".to_string()
            ]),
            FilesystemKind::Apfs => (true, true, false, true, true, vec![
                "APFS is copy-on-write with native snapshots; overwritten data may persist in snapshot-retained blocks.".to_string()
            ]),
            FilesystemKind::Tmpfs => (false, false, false, false, false, vec![
                "tmpfs is RAM-backed; data does not persist to physical storage but may be swapped to disk under memory pressure.".to_string()
            ]),
            FilesystemKind::Overlay => (false, true, false, false, false, vec![
                "OverlayFS (common in containers); the lower read-only layer is not modified by writes to the upper layer, so overwrite may not reach original data.".to_string()
            ]),
            FilesystemKind::Unknown => (false, false, false, false, false, vec![
                "Filesystem type could not be determined; sanitization strategy defaults to conservative multi-pass overwrite plus verification.".to_string()
            ]),
        };
        if cow || snapshots {
            notes.push("Recommendation: use crypto-erase or verify no snapshots/COW references remain before relying on overwrite alone.".to_string());
        }
        FilesystemInfo {
            path: path.to_path_buf(),
            kind,
            is_journaling: journaling,
            is_copy_on_write: cow,
            supports_dedup: dedup,
            supports_compression: compression,
            supports_snapshots: snapshots,
            notes,
        }
    }
}

pub fn detect_filesystem(path: &Path) -> FilesystemInfo {
    #[cfg(target_os = "linux")]
    {
        linux::detect(path)
    }
    #[cfg(target_os = "windows")]
    {
        windows::detect(path)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        FilesystemInfo::for_kind(path, FilesystemKind::Unknown)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;

    pub fn detect(path: &Path) -> FilesystemInfo {
        let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();

        let mut best: Option<(&str, &str)> = None;
        let mut best_len = 0usize;
        for line in mounts.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }
            let mount_point = fields[1];
            if canonical.starts_with(mount_point) && mount_point.len() >= best_len {
                best_len = mount_point.len();
                best = Some((fields[2], mount_point));
            }
        }

        let kind = match best.map(|(t, _)| t) {
            Some("ext4") | Some("ext3") | Some("ext2") => FilesystemKind::Ext4,
            Some("xfs") => FilesystemKind::Xfs,
            Some("btrfs") => FilesystemKind::Btrfs,
            Some("zfs") => FilesystemKind::Zfs,
            Some("f2fs") => FilesystemKind::F2fs,
            Some("ntfs") | Some("ntfs3") | Some("fuseblk") => FilesystemKind::Ntfs,
            Some("vfat") | Some("fat32") | Some("msdos") => FilesystemKind::Fat32,
            Some("exfat") => FilesystemKind::ExFat,
            Some("tmpfs") => FilesystemKind::Tmpfs,
            Some("overlay") => FilesystemKind::Overlay,
            _ => FilesystemKind::Unknown,
        };

        FilesystemInfo::for_kind(&canonical, kind)
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;

    /// Determining the exact FS type (NTFS vs ReFS vs FAT32/exFAT) on
    /// Windows uses GetVolumeInformationW, which lives in the platform
    /// abstraction layer's native bindings. Absent that call in this
    /// build, default to NTFS as the overwhelmingly common case for
    /// fixed/removable Windows volumes and note the limitation.
    pub fn detect(path: &Path) -> FilesystemInfo {
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let mut info = FilesystemInfo::for_kind(&canonical, FilesystemKind::Ntfs);
        info.notes.push("Assumed NTFS; call GetVolumeInformationW via the platform layer for definitive detection (NTFS/ReFS/FAT32/exFAT).".to_string());
        info
    }
}
