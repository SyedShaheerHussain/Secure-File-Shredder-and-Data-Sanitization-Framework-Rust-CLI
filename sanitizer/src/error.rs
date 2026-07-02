//! Centralized error handling for the sanitization framework.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SanitizerError {
    #[error("I/O error on '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("I/O error: {0}")]
    IoGeneric(#[from] std::io::Error),

    #[error("path does not exist: {0}")]
    PathNotFound(PathBuf),

    #[error("refusing to operate on protected path: {0}")]
    ProtectedPath(PathBuf),

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("vault error: {0}")]
    Vault(String),

    #[error("invalid vault password")]
    InvalidVaultPassword,

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("verification failed: {0}")]
    Verification(String),

    #[error("unsupported platform feature: {0}")]
    Unsupported(String),

    #[error("operation cancelled by user")]
    Cancelled,

    #[error("configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, SanitizerError>;

impl SanitizerError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        SanitizerError::Io {
            path: path.into(),
            source,
        }
    }
}
