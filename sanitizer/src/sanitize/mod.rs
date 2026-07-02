//! The sanitization engine: overwrite pattern strategies, single-file
//! shredding, recursive directory shredding with a thread pool, and
//! metadata sanitization (filename, timestamps).

pub mod patterns;
pub mod engine;
pub mod metadata;
pub mod directory;

pub use engine::{shred_file, ShredOptions, ShredOutcome};
pub use patterns::OverwritePattern;
