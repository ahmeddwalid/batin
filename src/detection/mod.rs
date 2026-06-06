//! Detection module
//!
//! Core file type detection functionality.
//!
//! - [`signatures`] - Magic byte database and signature matching
//! - [`entropy`] - Shannon entropy analysis
//! - [`polyglot`] - Multi-format polyglot detection
//! - [`embedded`] - Embedded threat scanning

pub mod detector;
pub mod embedded;
pub mod entropy;
pub mod polyglot;
pub mod signatures;
#[cfg(feature = "yara")]
pub mod yara;

// Re-exports for convenience
pub use detector::{register_detector, Detector};
pub use embedded::{EmbeddedThreat, ThreatType};
pub use entropy::{EntropyProfile, EntropyStats};
pub use polyglot::detect_polyglot;
pub use signatures::{
    load_user_signatures, FileCategory, FileSignature, SignatureDatabase, SignatureFile,
    SignatureSpec, SIGNATURE_DB,
};
#[cfg(feature = "yara")]
pub use yara::{register_yara_rules_from_file, YaraDetector};
