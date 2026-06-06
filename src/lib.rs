#![forbid(unsafe_code)]
#![warn(clippy::all)]

//! # Batin - Security-Hardened File Type Detection
//!
//! A professional library for detecting file types using magic bytes, Shannon entropy,
//! and advanced security features for cybersecurity applications.
//!
//! ## Features
//!
//! - **60+ File Formats**: Comprehensive signature database for images, documents, archives, executables, and multimedia
//! - **Entropy Analysis**: Shannon entropy calculation with sliding windows to detect packed/encrypted content
//! - **Polyglot Detection**: Identifies files valid in multiple formats simultaneously
//! - **Embedded Threats**: Scans for macros, scripts, and executables hidden in documents/archives
//! - **Content Validation**: Validates PDF, PNG, ZIP, PE structure beyond magic bytes
//! - **Zero Unsafe Code**: Built entirely with safe Rust for maximum security
//! - **Async & Parallel**: Tokio for I/O, Rayon for CPU-bound tasks
//!
//! ## Quick Example
//!
//! ```no_run
//! use batin::{FileType, DetectionConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = DetectionConfig::default();
//!     let file_type = FileType::from_file_path("suspicious.exe", &config).await?;
//!    
//!     println!("Type: {} ({})", file_type.extension, file_type.mime_type);
//!     println!("Threat Level: {:?}", file_type.threat_level);
//!    
//!     if let Some(entropy) = file_type.entropy_profile {
//!         if entropy.is_packed {
//!             println!("WARNING: File appears to be packed!");
//!         }
//!     }
//!    
//!     Ok(())
//! }
//! ```
//!
//! ## Module Organization
//!
//! - [`detection`] - Core file type detection (signatures, entropy, polyglot, embedded)
//! - [`analysis`] - File structure analysis (PE parsing, validation, forensics)
//! - [`io`] - I/O operations (archive scanning, batch processing, hashing)

#[cfg(feature = "async")]
use std::path::Path;
use thiserror::Error;

// ============================================================================
// Module Organization
// ============================================================================

/// Core file type detection functionality
pub mod detection;

/// File structure analysis and validation
pub mod analysis;

/// I/O operations and batch processing
#[path = "io/mod.rs"]
pub mod file_io;

/// Shared utilities
pub mod utils;

/// Online hash reputation lookups (VirusTotal).
#[cfg(feature = "online")]
pub mod reputation;

// ============================================================================
// Error Types
// ============================================================================

/// Detection error types with no panic guarantees
#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("File too large: {0} bytes (max: {1})")]
    FileTooLarge(u64, u64),

    #[error("Corrupted file structure: {0}")]
    CorruptedStructure(String),

    #[error("Unknown file format")]
    UnknownFormat,

    #[error("Extension mismatch: expected {expected}, got {actual}")]
    ExtensionMismatch { expected: String, actual: String },

    #[error("Timeout reading file")]
    Timeout,

    #[error("Invalid detection configuration: {0}")]
    InvalidConfig(String),
}

/// Result type alias for Batin operations
pub type Result<T> = std::result::Result<T, DetectionError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for detection behavior
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// Maximum bytes to read for detection (default: 3KB)
    pub max_read_bytes: usize,
    /// Enable Shannon entropy analysis
    pub enable_entropy: bool,
    /// Enable polyglot file detection
    pub enable_polyglot: bool,
    /// Enable embedded threat scanning
    pub enable_embedded: bool,
    /// Entropy threshold for packed/encrypted detection (default: 7.2)
    pub entropy_threshold: f64,
    /// Chi-square threshold for packed detection (default: 100.0)
    /// Files with chi-square below this and high entropy are likely packed
    pub packed_chi_square_threshold: f64,
    /// Entropy threshold for encrypted content detection (default: 7.8)
    /// Files above this entropy are likely encrypted
    pub encrypted_entropy_threshold: f64,
    /// Chi-square threshold for encrypted detection (default: 50.0)
    /// Files with very uniform distribution below this are likely encrypted
    pub encrypted_chi_square_threshold: f64,
    /// Timeout in milliseconds for file operations
    pub timeout_ms: u64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            max_read_bytes: 3072,
            enable_entropy: true,
            enable_polyglot: true,
            enable_embedded: true,
            entropy_threshold: 7.2,
            packed_chi_square_threshold: 100.0,
            encrypted_entropy_threshold: 7.8,
            encrypted_chi_square_threshold: 50.0,
            timeout_ms: 5000,
        }
    }
}

/// Maximum possible Shannon entropy for byte data (log2 of 256 symbols).
const MAX_ENTROPY_BITS: f64 = 8.0;

impl DetectionConfig {
    /// Validate the configuration, rejecting nonsensical or out-of-range values.
    ///
    /// Returns [`DetectionError::InvalidConfig`] describing the first problem found.
    pub fn validate(&self) -> Result<()> {
        if self.max_read_bytes == 0 {
            return Err(DetectionError::InvalidConfig(
                "max_read_bytes must be greater than 0".to_string(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(DetectionError::InvalidConfig(
                "timeout_ms must be greater than 0".to_string(),
            ));
        }

        for (name, value) in [
            ("entropy_threshold", self.entropy_threshold),
            (
                "encrypted_entropy_threshold",
                self.encrypted_entropy_threshold,
            ),
        ] {
            if !value.is_finite() || !(0.0..=MAX_ENTROPY_BITS).contains(&value) {
                return Err(DetectionError::InvalidConfig(format!(
                    "{name} must be within 0.0..={MAX_ENTROPY_BITS} (got {value})"
                )));
            }
        }

        for (name, value) in [
            (
                "packed_chi_square_threshold",
                self.packed_chi_square_threshold,
            ),
            (
                "encrypted_chi_square_threshold",
                self.encrypted_chi_square_threshold,
            ),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(DetectionError::InvalidConfig(format!(
                    "{name} must be a non-negative finite number (got {value})"
                )));
            }
        }

        if self.encrypted_entropy_threshold < self.entropy_threshold {
            return Err(DetectionError::InvalidConfig(format!(
                "encrypted_entropy_threshold ({}) must be >= entropy_threshold ({})",
                self.encrypted_entropy_threshold, self.entropy_threshold
            )));
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Builder-style setters (chainable, start from `DetectionConfig::default()`)
    // ------------------------------------------------------------------

    /// Set the maximum number of bytes to read for detection.
    ///
    /// ```
    /// use batin::DetectionConfig;
    /// let config = DetectionConfig::default()
    ///     .with_max_read_bytes(8192)
    ///     .with_entropy(false);
    /// assert_eq!(config.max_read_bytes, 8192);
    /// assert!(!config.enable_entropy);
    /// ```
    pub fn with_max_read_bytes(mut self, bytes: usize) -> Self {
        self.max_read_bytes = bytes;
        self
    }

    /// Enable or disable Shannon entropy analysis.
    pub fn with_entropy(mut self, enabled: bool) -> Self {
        self.enable_entropy = enabled;
        self
    }

    /// Enable or disable polyglot detection.
    pub fn with_polyglot(mut self, enabled: bool) -> Self {
        self.enable_polyglot = enabled;
        self
    }

    /// Enable or disable embedded-threat scanning.
    pub fn with_embedded(mut self, enabled: bool) -> Self {
        self.enable_embedded = enabled;
        self
    }

    /// Set the operation timeout in milliseconds.
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

// ============================================================================
// Core Types
// ============================================================================

/// Threat severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ThreatLevel {
    /// No detected threats
    Safe,
    /// Potentially suspicious characteristics
    Suspicious,
    /// Known dangerous patterns detected
    Dangerous,
    /// Critical threat (e.g., auto-execute macros)
    Critical,
}

/// Main detection result with comprehensive file information
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileType {
    /// Detected file extension
    pub extension: String,
    /// MIME type
    pub mime_type: String,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f64,
    /// Entropy analysis results
    pub entropy_profile: Option<detection::EntropyProfile>,
    /// Overall threat assessment
    pub threat_level: ThreatLevel,
    /// All detected formats (for polyglots)
    pub detected_formats: Vec<String>,
    /// Embedded threats found
    pub embedded_threats: Vec<detection::EmbeddedThreat>,
    /// File hashes (MD5, SHA-256, SHA-512)
    pub hashes: Option<file_io::hasher::FileHashes>,
    /// Binary metadata for PE/ELF files
    pub binary_metadata: Option<analysis::BinaryMetadata>,
    /// Non-fatal warnings raised during detection (e.g. extension mismatch).
    ///
    /// These do not fail detection but are surfaced for callers that don't
    /// configure a logger.
    #[serde(default)]
    pub warnings: Vec<String>,
}

// ============================================================================
// Detection API
// ============================================================================

impl FileType {
    /// Detect file type from byte slice
    pub fn from_bytes(data: &[u8], config: &DetectionConfig) -> Result<Self> {
        config.validate()?;
        Self::from_bytes_internal(data, None, config)
    }

    /// Detect file type from file path (async)
    ///
    /// Uses bounded async I/O to prevent memory exhaustion on large files.
    /// Only reads up to `config.max_read_bytes` from the file.
    ///
    /// Requires the `async` feature.
    #[cfg(feature = "async")]
    pub async fn from_file_path<P: AsRef<Path>>(path: P, config: &DetectionConfig) -> Result<Self> {
        use tokio::io::AsyncReadExt;

        config.validate()?;

        let path = path.as_ref();
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase());

        // Use bounded read to prevent memory exhaustion on large files
        let read_future = async {
            let file = tokio::fs::File::open(path).await?;
            let mut reader = tokio::io::BufReader::new(file).take(config.max_read_bytes as u64);
            let mut data = Vec::with_capacity(config.max_read_bytes);
            reader.read_to_end(&mut data).await?;
            Ok::<Vec<u8>, std::io::Error>(data)
        };

        let data = tokio::time::timeout(
            tokio::time::Duration::from_millis(config.timeout_ms),
            read_future,
        )
        .await
        .map_err(|_| DetectionError::Timeout)?
        .map_err(DetectionError::Io)?;

        Self::from_bytes_internal(&data, extension, config)
    }

    fn from_bytes_internal(
        data: &[u8],
        declared_ext: Option<String>,
        config: &DetectionConfig,
    ) -> Result<Self> {
        use detection::SIGNATURE_DB;

        // Stage 1: Magic byte matching
        let db = SIGNATURE_DB.read().map_err(|_| {
            DetectionError::CorruptedStructure("Signature database lock poisoned".to_string())
        })?;
        let matches = db.match_signatures(data);

        // If no signature matches, try text detection as fallback
        if matches.is_empty() {
            // Check if this looks like a text file
            if is_likely_text(data) {
                let text_type = detect_text_type(data, &declared_ext);

                // Stage 2: Entropy analysis
                let entropy_profile = if config.enable_entropy {
                    Some(detection::entropy::analyze_entropy(
                        data,
                        config.entropy_threshold,
                        config.packed_chi_square_threshold,
                        config.encrypted_entropy_threshold,
                        config.encrypted_chi_square_threshold,
                    )?)
                } else {
                    None
                };

                let mut warnings = Vec::new();
                if let Some(ref ext) = declared_ext {
                    if *ext != text_type.0 {
                        warnings.push(format!(
                            "Extension mismatch: file claims '{}' but detected '{}'",
                            ext, text_type.0
                        ));
                    }
                }

                // Run any registered custom detector stages.
                let embedded_threats = if config.enable_embedded {
                    detection::detector::run_custom_detectors(data)
                } else {
                    Vec::new()
                };
                let threat_level = Self::escalate_threat(ThreatLevel::Safe, &embedded_threats);

                return Ok(Self {
                    extension: text_type.0.to_string(),
                    mime_type: text_type.1.to_string(),
                    confidence: text_type.2,
                    entropy_profile,
                    threat_level,
                    detected_formats: vec![text_type.0.to_string()],
                    embedded_threats,
                    hashes: None,
                    binary_metadata: None,
                    warnings,
                });
            }
            return Err(DetectionError::UnknownFormat);
        }

        let (sig_idx, confidence) = matches[0];
        let signature = &db.signatures[sig_idx];

        // Stage 2: Entropy analysis with configurable thresholds
        let entropy_profile = if config.enable_entropy {
            Some(detection::entropy::analyze_entropy(
                data,
                config.entropy_threshold,
                config.packed_chi_square_threshold,
                config.encrypted_entropy_threshold,
                config.encrypted_chi_square_threshold,
            )?)
        } else {
            None
        };

        // Stage 3: Polyglot detection
        let detected_formats = if config.enable_polyglot {
            detection::polyglot::detect_polyglot(data, &db)?
        } else {
            vec![signature.extensions[0].clone()]
        };

        // Stage 4: Threat assessment
        let mut threat_level = Self::assess_threat(signature, &entropy_profile, &detected_formats);

        // Stage 5: Embedded content scanning (built-in + registered custom stages)
        let embedded_threats = if config.enable_embedded {
            let mut threats = detection::embedded::scan_embedded_content(data, signature)?;
            threats.extend(detection::detector::run_custom_detectors(data));
            threats
        } else {
            Vec::new()
        };

        // Custom/embedded findings can escalate the overall threat level.
        threat_level = Self::escalate_threat(threat_level, &embedded_threats);

        // Extension mismatch detection
        let mut warnings = Vec::new();
        if let Some(ref ext) = declared_ext {
            if !signature.extensions.contains(ext) {
                let message = format!(
                    "Extension mismatch: file claims '{}' but detected '{}'",
                    ext, signature.extensions[0]
                );
                log::warn!("{message}");
                warnings.push(message);
            }
        }

        Ok(Self {
            extension: signature.extensions[0].clone(),
            mime_type: signature.mime_type.clone(),
            confidence,
            entropy_profile,
            threat_level,
            detected_formats,
            embedded_threats,
            hashes: None,
            binary_metadata: None,
            warnings,
        })
    }

    /// Numeric rank for ordering threat levels.
    fn threat_rank(level: ThreatLevel) -> u8 {
        match level {
            ThreatLevel::Safe => 0,
            ThreatLevel::Suspicious => 1,
            ThreatLevel::Dangerous => 2,
            ThreatLevel::Critical => 3,
        }
    }

    /// Raise `current` to the highest severity among `threats`, if greater.
    fn escalate_threat(current: ThreatLevel, threats: &[detection::EmbeddedThreat]) -> ThreatLevel {
        threats
            .iter()
            .map(|t| t.severity)
            .fold(current, |acc, sev| {
                if Self::threat_rank(sev) > Self::threat_rank(acc) {
                    sev
                } else {
                    acc
                }
            })
    }

    fn assess_threat(
        signature: &detection::FileSignature,
        entropy_profile: &Option<detection::EntropyProfile>,
        detected_formats: &[String],
    ) -> ThreatLevel {
        use detection::FileCategory;

        let mut threat = ThreatLevel::Safe;

        if signature.category == FileCategory::Executable {
            threat = ThreatLevel::Suspicious;
        }

        if let Some(profile) = entropy_profile {
            if profile.global_entropy > 7.5 && signature.category == FileCategory::Executable {
                threat = ThreatLevel::Dangerous;
            }
        }

        if detected_formats.len() > 1 {
            threat = ThreatLevel::Dangerous;
        }

        threat
    }

    /// Validate that claimed extension matches detected content
    pub fn validate_extension(&self, claimed_ext: &str) -> bool {
        self.extension == claimed_ext || self.detected_formats.contains(&claimed_ext.to_string())
    }
}

// ============================================================================
// Text File Detection Helpers
// ============================================================================

/// Check if data is likely a text file by examining byte patterns
fn is_likely_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Sample up to first 1024 bytes
    let sample_size = data.len().min(1024);
    let sample = &data[..sample_size];

    // Count printable ASCII and common text bytes
    let mut text_chars = 0;
    let mut binary_chars = 0;

    for &byte in sample {
        match byte {
            // Printable ASCII (space to tilde) + common whitespace
            0x20..=0x7E | 0x09 | 0x0A | 0x0D => text_chars += 1,
            // UTF-8 continuation bytes (0x80-0xBF) and start bytes (0xC0-0xF7)
            0x80..=0xF7 => text_chars += 1, // Allow UTF-8 multibyte
            // Null byte is a strong indicator of binary
            0x00 => binary_chars += 10, // Weight null heavily
            // Other control characters suggest binary (including DEL = 0x7F)
            0x01..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F => binary_chars += 1,
            // High bytes (0xF8-0xFF) are invalid UTF-8
            0xF8..=0xFF => binary_chars += 2,
        }
    }

    // Consider it text if >85% are text characters and few binary indicators
    let text_ratio = text_chars as f64 / sample_size as f64;
    text_ratio > 0.85 && binary_chars < (sample_size / 10)
}

/// Detect specific text format based on content patterns
fn detect_text_type(
    data: &[u8],
    declared_ext: &Option<String>,
) -> (&'static str, &'static str, f64) {
    let content = String::from_utf8_lossy(data);
    let trimmed = content.trim_start();

    // Check for specific text formats by content patterns
    // JSON
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && (content.contains("\":") || content.contains("\": "))
    {
        return ("json", "application/json", 0.9);
    }

    // HTML
    if trimmed.starts_with("<!DOCTYPE html")
        || trimmed.starts_with("<!doctype html")
        || trimmed.starts_with("<html")
        || trimmed.starts_with("<HTML")
    {
        return ("html", "text/html", 0.95);
    }

    // XML (but not SVG which has its own signature)
    if trimmed.starts_with("<?xml") {
        if content.contains("<svg") {
            return ("svg", "image/svg+xml", 0.9);
        }
        return ("xml", "application/xml", 0.9);
    }

    // Markdown (common patterns)
    if trimmed.starts_with('#')
        || content.contains("\n# ")
        || content.contains("\n## ")
        || content.contains("\n```")
        || content.contains("\n- ")
        || content.contains("\n* ")
    {
        return ("md", "text/markdown", 0.7);
    }

    // YAML
    if content.contains(":\n")
        && (content.contains("  ") || content.contains("\n- "))
        && !content.contains('{')
        && !content.contains('[')
    {
        return ("yaml", "application/x-yaml", 0.7);
    }

    // Shell script
    if trimmed.starts_with("#!/bin/bash")
        || trimmed.starts_with("#!/bin/sh")
        || trimmed.starts_with("#!/usr/bin/env bash")
        || trimmed.starts_with("#!/usr/bin/env sh")
    {
        return ("sh", "application/x-sh", 0.95);
    }

    // Python script
    if (trimmed.starts_with("#!/usr/bin/env python")
        || trimmed.starts_with("#!/usr/bin/python")
        || (content.contains("def ") && content.contains(":"))
        || content.contains("import "))
        && declared_ext.as_deref() == Some("py")
    {
        return ("py", "text/x-python", 0.85);
    }

    // CSS
    if content.contains('{')
        && content.contains('}')
        && (content.contains("color:")
            || content.contains("margin:")
            || content.contains("padding:"))
    {
        return ("css", "text/css", 0.7);
    }

    // JavaScript/TypeScript (basic detection)
    if content.contains("function ")
        || content.contains("const ")
        || content.contains("let ")
        || content.contains("=>")
        || content.contains("export ")
    {
        if declared_ext.as_deref() == Some("ts") || declared_ext.as_deref() == Some("tsx") {
            return ("ts", "text/typescript", 0.7);
        }
        if declared_ext.as_deref() == Some("js") || declared_ext.as_deref() == Some("jsx") {
            return ("js", "text/javascript", 0.7);
        }
    }

    // INI/Config files
    if trimmed.starts_with('[') && content.contains("]\n") && content.contains('=') {
        return ("ini", "text/plain", 0.7);
    }

    // TOML
    if content.contains("[")
        && content.contains("]\n")
        && content.contains(" = ")
        && declared_ext.as_deref() == Some("toml")
    {
        return ("toml", "application/toml", 0.8);
    }

    // CSV (basic detection)
    if content.lines().take(5).all(|line| line.contains(',')) {
        let comma_counts: Vec<_> = content
            .lines()
            .take(5)
            .map(|l| l.matches(',').count())
            .collect();
        if comma_counts.len() > 1 && comma_counts.iter().all(|&c| c == comma_counts[0]) {
            return ("csv", "text/csv", 0.7);
        }
    }

    // Log files
    if declared_ext.as_deref() == Some("log") {
        return ("log", "text/plain", 0.8);
    }

    // Use declared extension if available and it's a known text type
    if let Some(ext) = declared_ext {
        match ext.as_str() {
            "txt" => return ("txt", "text/plain", 0.9),
            "md" | "markdown" => return ("md", "text/markdown", 0.85),
            "json" => return ("json", "application/json", 0.8),
            "xml" => return ("xml", "application/xml", 0.8),
            "html" | "htm" => return ("html", "text/html", 0.8),
            "css" => return ("css", "text/css", 0.8),
            "js" => return ("js", "text/javascript", 0.8),
            "ts" => return ("ts", "text/typescript", 0.8),
            "py" => return ("py", "text/x-python", 0.8),
            "rs" => return ("rs", "text/x-rust", 0.8),
            "go" => return ("go", "text/x-go", 0.8),
            "c" | "h" => return ("c", "text/x-c", 0.8),
            "cpp" | "hpp" | "cc" | "cxx" => return ("cpp", "text/x-c++", 0.8),
            "java" => return ("java", "text/x-java", 0.8),
            "rb" => return ("rb", "text/x-ruby", 0.8),
            "php" => return ("php", "text/x-php", 0.8),
            "sh" | "bash" => return ("sh", "application/x-sh", 0.8),
            "yaml" | "yml" => return ("yaml", "application/x-yaml", 0.8),
            "toml" => return ("toml", "application/toml", 0.8),
            "ini" | "cfg" | "conf" => return ("ini", "text/plain", 0.8),
            "csv" => return ("csv", "text/csv", 0.8),
            "sql" => return ("sql", "application/sql", 0.8),
            "dockerfile" => return ("dockerfile", "text/x-dockerfile", 0.8),
            _ => {}
        }
    }

    // Default to plain text
    ("txt", "text/plain", 0.6)
}

// ============================================================================
// Re-exports (Prelude)
// ============================================================================

// Detection module re-exports
pub use detection::{
    load_user_signatures, register_detector, Detector, EmbeddedThreat, EntropyProfile,
    EntropyStats, FileCategory, FileSignature, SignatureDatabase, SignatureFile, SignatureSpec,
    ThreatType, SIGNATURE_DB,
};

#[cfg(feature = "yara")]
pub use detection::{register_yara_rules_from_file, YaraDetector};

// Analysis module re-exports
#[cfg(feature = "binary-parsing")]
pub use analysis::parse_binary;
pub use analysis::{classify_fragment, BinaryFormat, BinaryMetadata};

// I/O module re-exports
pub use file_io::{
    archive::{self, ArchiveConfig},
    hasher,
};

#[cfg(feature = "async")]
pub use file_io::batch::{BatchProcessor, BatchProgress};

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(DetectionConfig::default().validate().is_ok());
    }

    #[test]
    fn rejects_zero_max_read_bytes() {
        let config = DetectionConfig {
            max_read_bytes: 0,
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(DetectionError::InvalidConfig(_))
        ));
    }

    #[test]
    fn rejects_out_of_range_entropy_threshold() {
        let config = DetectionConfig {
            entropy_threshold: 9.0,
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(DetectionError::InvalidConfig(_))
        ));
    }

    #[test]
    fn rejects_inverted_entropy_thresholds() {
        let config = DetectionConfig {
            entropy_threshold: 7.5,
            encrypted_entropy_threshold: 7.0,
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(DetectionError::InvalidConfig(_))
        ));
    }

    #[test]
    fn from_bytes_rejects_invalid_config() {
        let config = DetectionConfig {
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(matches!(
            FileType::from_bytes(b"hello", &config),
            Err(DetectionError::InvalidConfig(_))
        ));
    }
}
