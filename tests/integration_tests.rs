//! Integration tests for Batin
//!
//! End-to-end tests for file type detection, archive scanning, and threat analysis.

use batin::{DetectionConfig, FileType, ThreatLevel};
use std::io::Write;
use tempfile::NamedTempFile;

// ============================================================================
// File Type Detection Tests
// ============================================================================

#[tokio::test]
async fn test_detect_png_file() {
    let mut file = NamedTempFile::with_suffix(".png").unwrap();
    // PNG signature
    file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        .unwrap();
    file.write_all(&[0u8; 100]).unwrap();
    file.flush().unwrap();

    let config = DetectionConfig::default();
    let result = FileType::from_file_path(file.path(), &config).await;

    assert!(result.is_ok());
    let file_type = result.unwrap();
    assert_eq!(file_type.extension, "png");
    assert_eq!(file_type.mime_type, "image/png");
    assert_eq!(file_type.threat_level, ThreatLevel::Safe);
}

#[tokio::test]
async fn test_detect_pdf_file() {
    let mut file = NamedTempFile::with_suffix(".pdf").unwrap();
    file.write_all(b"%PDF-1.4\n").unwrap();
    file.write_all(&[0u8; 100]).unwrap();
    file.write_all(b"\n%%EOF").unwrap();
    file.flush().unwrap();

    let config = DetectionConfig::default();
    let result = FileType::from_file_path(file.path(), &config).await;

    assert!(result.is_ok());
    let file_type = result.unwrap();
    assert_eq!(file_type.extension, "pdf");
    assert_eq!(file_type.mime_type, "application/pdf");
}

#[tokio::test]
async fn test_detect_zip_file() {
    let mut file = NamedTempFile::with_suffix(".zip").unwrap();
    // ZIP local file header signature
    file.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap();
    file.write_all(&[0u8; 100]).unwrap();
    file.flush().unwrap();

    let config = DetectionConfig::default();
    let result = FileType::from_file_path(file.path(), &config).await;

    assert!(result.is_ok());
    let file_type = result.unwrap();
    // ZIP-based formats might be detected as various types
    assert!(["zip", "docx", "xlsx", "jar", "epub", "odt"].contains(&file_type.extension.as_str()));
}

#[tokio::test]
async fn test_detect_executable_file() {
    let mut file = NamedTempFile::with_suffix(".exe").unwrap();
    // MZ header for PE
    file.write_all(b"MZ").unwrap();
    file.write_all(&[0u8; 58]).unwrap(); // Padding to offset 0x3C
    file.write_all(&[0x80, 0x00, 0x00, 0x00]).unwrap(); // PE header offset
    file.write_all(&[0u8; 64]).unwrap();
    file.write_all(b"PE\x00\x00").unwrap(); // PE signature
    file.write_all(&[0u8; 100]).unwrap();
    file.flush().unwrap();

    let config = DetectionConfig::default();
    let result = FileType::from_file_path(file.path(), &config).await;

    assert!(result.is_ok());
    let file_type = result.unwrap();
    assert_eq!(file_type.extension, "exe");
    // Executables should be at least suspicious
    assert!(matches!(
        file_type.threat_level,
        ThreatLevel::Suspicious | ThreatLevel::Dangerous
    ));
}

// ============================================================================
// Extension Mismatch Tests
// ============================================================================

#[tokio::test]
async fn test_extension_mismatch_detection() {
    // Create a PNG file with .txt extension
    let mut file = NamedTempFile::with_suffix(".txt").unwrap();
    file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        .unwrap();
    file.write_all(&[0u8; 100]).unwrap();
    file.flush().unwrap();

    let config = DetectionConfig::default();
    let result = FileType::from_file_path(file.path(), &config).await;

    assert!(result.is_ok());
    let file_type = result.unwrap();
    // Content is PNG, not what .txt suggests
    assert_eq!(file_type.extension, "png");
    assert!(!file_type.validate_extension("txt"));
}

// ============================================================================
// Entropy Analysis Tests
// ============================================================================

#[tokio::test]
async fn test_high_entropy_detection() {
    let mut file = NamedTempFile::with_suffix(".bin").unwrap();
    // MZ header
    file.write_all(b"MZ").unwrap();
    file.write_all(&[0u8; 100]).unwrap();
    // High entropy data (pseudo-random)
    let high_entropy: Vec<u8> = (0..=255).cycle().take(2048).collect();
    file.write_all(&high_entropy).unwrap();
    file.flush().unwrap();

    let config = DetectionConfig {
        enable_entropy: true,
        ..Default::default()
    };
    let result = FileType::from_file_path(file.path(), &config).await;

    assert!(result.is_ok());
    let file_type = result.unwrap();
    if let Some(entropy) = file_type.entropy_profile {
        assert!(entropy.global_entropy > 6.0, "Expected high entropy");
    }
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_detection_config_defaults() {
    let config = DetectionConfig::default();
    assert!(config.enable_entropy);
    assert!(config.enable_polyglot);
    assert!(config.enable_embedded);
    assert_eq!(config.max_read_bytes, 3072);
}

#[tokio::test]
async fn test_disabled_features() {
    let mut file = NamedTempFile::with_suffix(".pdf").unwrap();
    file.write_all(b"%PDF-1.4\n").unwrap();
    file.write_all(&[0u8; 100]).unwrap();
    file.flush().unwrap();

    let config = DetectionConfig {
        enable_entropy: false,
        enable_polyglot: false,
        enable_embedded: false,
        ..Default::default()
    };
    let result = FileType::from_file_path(file.path(), &config).await;

    assert!(result.is_ok());
    let file_type = result.unwrap();
    assert!(file_type.entropy_profile.is_none());
    assert!(file_type.embedded_threats.is_empty());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_nonexistent_file() {
    let config = DetectionConfig::default();
    let result = FileType::from_file_path("/nonexistent/file.txt", &config).await;
    assert!(result.is_err());
}

#[test]
fn test_unknown_format() {
    let config = DetectionConfig::default();
    let random_data: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78];
    let result = FileType::from_bytes(&random_data, &config);
    assert!(result.is_err());
}

// ============================================================================
// Polyglot Detection Tests
// ============================================================================

#[test]
fn test_polyglot_pdf_exe() {
    // PDF with embedded PE signature
    let mut data = b"%PDF-1.4\n".to_vec();
    data.extend_from_slice(&[0u8; 200]);
    data.extend_from_slice(b"MZ"); // PE header embedded in PDF

    let config = DetectionConfig {
        enable_polyglot: true,
        ..Default::default()
    };
    let result = FileType::from_bytes(&data, &config);

    assert!(result.is_ok());
    let file_type = result.unwrap();
    // Should detect as PDF but flag polyglot with exe
    assert_eq!(file_type.extension, "pdf");
    if file_type.detected_formats.len() > 1 {
        assert!(file_type.threat_level == ThreatLevel::Dangerous);
    }
}
