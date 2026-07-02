//! Storage technology and filesystem detection: HDD/SSD/NVMe classification,
//! filesystem type identification, and TRIM/discard capability probing.

pub mod device;
pub mod filesystem;

pub use device::{detect_storage_for_path, StorageInfo, StorageKind};
pub use filesystem::{detect_filesystem, FilesystemInfo, FilesystemKind};
