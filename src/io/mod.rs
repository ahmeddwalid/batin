//! I/O module
//!
//! File I/O operations and batch processing.
//!
//! - [`archive`] - ZIP/TAR archive scanning
//! - [`batch`] - Parallel batch processing
//! - [`hasher`] - Hash calculation (MD5, SHA-256, SHA-512)

pub mod archive;
#[cfg(feature = "async")]
pub mod batch;
pub mod hasher;

// Re-exports
#[cfg(feature = "archive")]
pub use archive::{scan_archive, scan_archive_with_config};
pub use archive::{ArchiveConfig, ArchiveEntry};
#[cfg(feature = "async")]
pub use batch::{BatchProcessor, BatchProgress};
#[cfg(feature = "hashing")]
pub use hasher::calculate_hashes;
pub use hasher::FileHashes;
