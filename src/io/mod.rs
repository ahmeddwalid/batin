//! I/O module
//!
//! File I/O operations and batch processing.
//!
//! - [`archive`] - ZIP/TAR archive scanning
//! - [`batch`] - Parallel batch processing
//! - [`hasher`] - Hash calculation (MD5, SHA-256, SHA-512)

pub mod archive;
pub mod batch;
pub mod hasher;

// Re-exports
pub use archive::{scan_archive, ArchiveEntry};
pub use batch::{BatchProcessor, BatchProgress};
pub use hasher::{calculate_hashes, FileHashes};
