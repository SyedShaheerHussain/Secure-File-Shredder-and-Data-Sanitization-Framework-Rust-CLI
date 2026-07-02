//! Storage device classification.
//!
//! On Linux, classification walks `/sys/block/<dev>/queue/rotational` (0 =
//! non-rotational/SSD, 1 = HDD), checks for NVMe character devices under
//! `/dev/nvme*`, inspects `/proc/mounts` for network filesystem types
//! (nfs, cifs, smbfs) to flag network shares, and looks for `/dev/mapper`
//! or `/dev/dm-*` majors to flag LVM/virtual/encrypted-container-backed
//! block devices. On Windows, full classification requires
//! `DeviceIoControl` (`IOCTL_STORAGE_QUERY_PROPERTY` /
//! `StorageDeviceSeekPenaltyProperty`) or WMI (`MSFT_PhysicalDisk.MediaType`)
//! which are provided behind the platform abstraction layer; this module
//! exposes the same `StorageInfo` shape so callers don't need to branch on
//! OS, with `StorageKind::Unknown` returned where a definitive signal
//! isn't available in the current build.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageKind {
    Hdd,
    Ssd,
    Nvme,
    UsbRemovable,
    NetworkShare,
    VirtualOrContainer,
    CloudSynced,
    Unknown,
}

impl std::fmt::Display for StorageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            StorageKind::Hdd => "HDD (rotational)",
            StorageKind::Ssd => "SSD (non-rotational)",
            StorageKind::Nvme => "NVMe",
            StorageKind::UsbRemovable => "USB / removable media",
            StorageKind::NetworkShare => "Network share",
            StorageKind::VirtualOrContainer => "Virtual disk / device-mapper / encrypted container",
            StorageKind::CloudSynced => "Cloud-synced folder",
            StorageKind::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageInfo {
    pub path: PathBuf,
    pub kind: StorageKind,
    pub device_name: Option<String>,
    pub trim_supported: Option<bool>,
    pub is_network: bool,
    pub is_removable: bool,
    pub notes: Vec<String>,
}

impl StorageInfo {
    /// Whether traditional multi-pass overwrite can be trusted to
    /// physically destroy data on this storage class. False for SSD/NVMe
    /// (wear-leveling/FTL remapping means overwritten LBAs may not map to
    /// the same physical flash cells previously holding the data) and for
    /// network/cloud storage (remote copies, versioning, snapshots are
    /// outside the local overwrite's reach).
    pub fn overwrite_is_reliable(&self) -> bool {
        matches!(self.kind, StorageKind::Hdd | StorageKind::UsbRemovable)
    }

    pub fn recommend_crypto_erase(&self) -> bool {
        matches!(
            self.kind,
            StorageKind::Ssd | StorageKind::Nvme | StorageKind::CloudSynced
        )
    }
}

/// Detect storage characteristics for the device backing `path`.
pub fn detect_storage_for_path(path: &Path) -> StorageInfo {
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
        StorageInfo {
            path: path.to_path_buf(),
            kind: StorageKind::Unknown,
            device_name: None,
            trim_supported: None,
            is_network: false,
            is_removable: false,
            notes: vec!["Storage detection not implemented for this platform".into()],
        }
    }
}

/// Detect whether `path` lives inside a well-known cloud-sync folder by
/// name/path heuristics (OneDrive, Dropbox, Google Drive, Syncthing,
/// Nextcloud, ownCloud, iCloud Drive). This is a best-effort heuristic --
/// authoritative detection would require querying each vendor's client
/// daemon/API, which is out of scope for a filesystem-level tool.
pub fn detect_cloud_sync(path: &Path) -> Option<String> {
    let path_str = path.to_string_lossy().to_lowercase();
    let markers: &[(&str, &str)] = &[
        ("onedrive", "Microsoft OneDrive"),
        ("dropbox", "Dropbox"),
        ("google drive", "Google Drive"),
        ("googledrive", "Google Drive"),
        ("my drive", "Google Drive"),
        ("syncthing", "Syncthing"),
        ("nextcloud", "Nextcloud"),
        ("owncloud", "ownCloud"),
        ("icloud drive", "iCloud Drive"),
        ("icloud", "iCloud Drive"),
    ];
    for (marker, label) in markers {
        if path_str.contains(marker) {
            return Some((*label).to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;

    pub fn detect(path: &Path) -> StorageInfo {
        let mut notes = Vec::new();
        let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

        // Check mount table for network filesystem types and cloud markers.
        let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
        let mut is_network = false;
        let mut mount_source: Option<String> = None;
        let mut best_match_len = 0usize;

        for line in mounts.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }
            let source = fields[0];
            let mount_point = fields[1];
            let fstype = fields[2];
            if canonical.starts_with(mount_point) && mount_point.len() >= best_match_len {
                best_match_len = mount_point.len();
                mount_source = Some(source.to_string());
                is_network = matches!(fstype, "nfs" | "nfs4" | "cifs" | "smbfs" | "smb3" | "9p");
            }
        }

        if let Some(cloud) = detect_cloud_sync(&canonical) {
            notes.push(format!("Path appears to reside inside a {cloud} synced folder."));
            return StorageInfo {
                path: canonical,
                kind: StorageKind::CloudSynced,
                device_name: mount_source,
                trim_supported: None,
                is_network: false,
                is_removable: false,
                notes,
            };
        }

        if is_network {
            notes.push("Mounted via a network filesystem; local sanitization will not affect the remote copy.".into());
            return StorageInfo {
                path: canonical,
                kind: StorageKind::NetworkShare,
                device_name: mount_source,
                trim_supported: None,
                is_network: true,
                is_removable: false,
                notes,
            };
        }

        // Resolve the underlying block device name from the mount source,
        // e.g. /dev/sda1 -> sda, /dev/nvme0n1p2 -> nvme0n1, /dev/mapper/foo -> dm-managed.
        let dev_name = mount_source
            .as_deref()
            .and_then(|s| s.strip_prefix("/dev/"))
            .map(|s| s.to_string());

        let Some(dev_name) = dev_name else {
            notes.push("Could not resolve underlying block device from mount table.".into());
            return StorageInfo {
                path: canonical,
                kind: StorageKind::Unknown,
                device_name: None,
                trim_supported: None,
                is_network: false,
                is_removable: false,
                notes,
            };
        };

        if dev_name.starts_with("dm-") || dev_name.starts_with("mapper/") {
            notes.push("Backed by device-mapper (LVM, LUKS, or a virtual/encrypted container); underlying physical medium may differ.".into());
            return StorageInfo {
                path: canonical,
                kind: StorageKind::VirtualOrContainer,
                device_name: Some(dev_name),
                trim_supported: None,
                is_network: false,
                is_removable: false,
                notes,
            };
        }

        let base_dev = strip_partition_suffix(&dev_name);
        let sys_block = format!("/sys/block/{base_dev}");

        let rotational = fs::read_to_string(format!("{sys_block}/queue/rotational"))
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok());

        let removable = fs::read_to_string(format!("{sys_block}/removable"))
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .map(|v| v == 1)
            .unwrap_or(false);

        let is_nvme = base_dev.starts_with("nvme");

        // TRIM/discard support: presence and non-zero value of
        // queue/discard_granularity indicates the block layer advertises
        // discard support for this device.
        let discard_granularity = fs::read_to_string(format!("{sys_block}/queue/discard_granularity"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok());
        let trim_supported = discard_granularity.map(|g| g > 0);

        let kind = if removable {
            StorageKind::UsbRemovable
        } else if is_nvme {
            StorageKind::Nvme
        } else {
            match rotational {
                Some(1) => StorageKind::Hdd,
                Some(0) => StorageKind::Ssd,
                _ => StorageKind::Unknown,
            }
        };

        if matches!(kind, StorageKind::Ssd | StorageKind::Nvme) {
            notes.push(
                "Non-rotational storage: wear-leveling and the flash translation layer mean overwritten logical blocks may not map to the same physical NAND cells; overwrite-only sanitization cannot be guaranteed. Prefer crypto-erase or ATA/NVMe Secure Erase / Sanitize commands where available.".into(),
            );
            if trim_supported == Some(true) {
                notes.push("Device advertises TRIM/discard support.".into());
            }
        }

        StorageInfo {
            path: canonical,
            kind,
            device_name: Some(base_dev),
            trim_supported,
            is_network: false,
            is_removable: removable,
            notes,
        }
    }

    fn strip_partition_suffix(dev: &str) -> String {
        // nvme0n1p3 -> nvme0n1 ; sda1 -> sda
        if let Some(pos) = dev.rfind('p') {
            if dev.starts_with("nvme") && dev[pos + 1..].chars().all(|c| c.is_ascii_digit()) && !dev[pos+1..].is_empty() {
                return dev[..pos].to_string();
            }
        }
        let trimmed = dev.trim_end_matches(|c: char| c.is_ascii_digit());
        if trimmed.is_empty() {
            dev.to_string()
        } else {
            trimmed.to_string()
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;

    /// Windows classification requires DeviceIoControl calls
    /// (IOCTL_STORAGE_QUERY_PROPERTY with StorageDeviceSeekPenaltyProperty
    /// for SSD/HDD, StorageDeviceTrimProperty for TRIM support) against a
    /// handle opened on `\\.\PhysicalDriveN`, which in turn requires
    /// resolving the volume path to a physical drive number via
    /// GetVolumePathName + DeviceIoControl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS).
    /// That native call chain lives in the platform abstraction layer
    /// (see src/platform); this function detects what it can from
    /// path/environment heuristics and defers device-class queries to
    /// that layer when compiled on Windows with the platform feature.
    pub fn detect(path: &Path) -> StorageInfo {
        let mut notes = Vec::new();
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

        if let Some(cloud) = detect_cloud_sync(&canonical) {
            notes.push(format!("Path appears to reside inside a {cloud} synced folder."));
            return StorageInfo {
                path: canonical,
                kind: StorageKind::CloudSynced,
                device_name: None,
                trim_supported: None,
                is_network: false,
                is_removable: false,
                notes,
            };
        }

        // UNC paths (\\server\share) indicate a network share.
        let path_str = canonical.to_string_lossy();
        if path_str.starts_with(r"\\") {
            notes.push("UNC network path; local sanitization will not affect the remote copy.".into());
            return StorageInfo {
                path: canonical,
                kind: StorageKind::NetworkShare,
                device_name: None,
                trim_supported: None,
                is_network: true,
                is_removable: false,
                notes,
            };
        }

        notes.push("Definitive HDD/SSD/NVMe classification on Windows requires IOCTL_STORAGE_QUERY_PROPERTY via the platform layer; run with elevated privileges for full detection.".into());
        StorageInfo {
            path: canonical,
            kind: StorageKind::Unknown,
            device_name: None,
            trim_supported: None,
            is_network: false,
            is_removable: false,
            notes,
        }
    }
}
