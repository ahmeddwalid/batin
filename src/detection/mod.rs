//! Detection module
//!
//! Core file type detection functionality.
//!
//! - [`signatures`] - Magic byte database and signature matching
//! - [`entropy`] - Shannon entropy analysis
//! - [`polyglot`] - Multi-format polyglot detection
//! - [`embedded`] - Embedded threat scanning

pub mod embedded;
pub mod entropy;
pub mod polyglot;
pub mod signatures;

// Re-exports for convenience
pub use embedded::{EmbeddedThreat, ThreatType};
pub use entropy::{EntropyProfile, EntropyStats};
pub use polyglot::detect_polyglot;
pub use signatures::{FileCategory, FileSignature, SignatureDatabase, SIGNATURE_DB};
