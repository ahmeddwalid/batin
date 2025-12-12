//! Archive recursion module
//!
//! Scans inside archive files (ZIP, TAR, etc.) recursively to detect nested threats.
//! Includes protection against zip bombs and memory exhaustion.

use crate::{DetectionConfig, FileType, Result};
use std::io::{Cursor, Read};
use zip::ZipArchive;

/// Maximum size of a single extracted file (50MB)
const MAX_EXTRACTED_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Maximum total extracted size per archive (500MB)
const MAX_TOTAL_EXTRACTED_SIZE: u64 = 500 * 1024 * 1024;

/// Maximum number of entries to process in an archive
const MAX_ARCHIVE_ENTRIES: usize = 10_000;

/// Minimum compression ratio that indicates potential zip bomb (0.01 = 1%)
const SUSPICIOUS_COMPRESSION_RATIO: f64 = 0.01;

/// Archive entry information
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchiveEntry {
    /// Path within archive
    pub path: String,
    /// Detected file type
    pub file_type: Option<FileType>,
    /// File size in bytes
    pub size: u64,
    /// Compression ratio (compressed_size / uncompressed_size)
    pub compression_ratio: f64,
    /// Whether this entry was skipped due to size limits
    pub skipped: bool,
}

/// Scan archive contents recursively
///
/// # Arguments
/// * `data` - Archive file data
/// * `max_depth` - Maximum recursion depth (prevents zip bombs)
/// * `config` - Detection configuration
///
/// # Examples
/// ```no_run
/// use batin::{archive::scan_archive, DetectionConfig};
///
/// let zip_data = std::fs::read("archive.zip").unwrap();
/// let config = DetectionConfig::default();
/// let entries = scan_archive(&zip_data, 3, &config).unwrap();
///
/// for entry in entries {
///     println!("{}: {:?}", entry.path, entry.file_type);
/// }
/// ```
pub fn scan_archive(
    data: &[u8],
    max_depth: usize,
    config: &DetectionConfig,
) -> Result<Vec<ArchiveEntry>> {
    scan_zip(data, max_depth, config, 0)
}

fn scan_zip(
    data: &[u8],
    max_depth: usize,
    config: &DetectionConfig,
    current_depth: usize,
) -> Result<Vec<ArchiveEntry>> {
    scan_zip_with_limits(data, max_depth, config, current_depth, &mut 0)
}

/// Internal function that tracks total extracted size across recursive calls
fn scan_zip_with_limits(
    data: &[u8],
    max_depth: usize,
    config: &DetectionConfig,
    current_depth: usize,
    total_extracted: &mut u64,
) -> Result<Vec<ArchiveEntry>> {
    if current_depth >= max_depth {
        return Ok(Vec::new());
    }

    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| {
        crate::DetectionError::CorruptedStructure(format!("Failed to read ZIP: {}", e))
    })?;

    let mut entries = Vec::new();
    let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);

    // Early zip bomb detection: check total claimed size before extraction
    // We calculate this by iterating through entries and summing claimed sizes
    let mut total_claimed_size: u64 = 0;
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            total_claimed_size += file.size();
        }
    }

    if total_claimed_size > MAX_TOTAL_EXTRACTED_SIZE {
        log::warn!(
            "Archive claims {} bytes uncompressed, exceeds limit of {} bytes",
            total_claimed_size,
            MAX_TOTAL_EXTRACTED_SIZE
        );
        // Return early with a warning entry
        return Ok(vec![ArchiveEntry {
            path: "[ARCHIVE TOO LARGE]".to_string(),
            file_type: None,
            size: total_claimed_size,
            compression_ratio: 0.0,
            skipped: true,
        }]);
    }

    for i in 0..entry_count {
        // Re-open archive for each entry (ZipArchive borrows mutably)
        let cursor = Cursor::new(data);
        let mut archive = ZipArchive::new(cursor).map_err(|e| {
            crate::DetectionError::CorruptedStructure(format!("Failed to read ZIP: {}", e))
        })?;

        let mut file = archive.by_index(i).map_err(|e| {
            crate::DetectionError::CorruptedStructure(format!("Failed to read ZIP entry: {}", e))
        })?;

        let path = file.name().to_string();
        let size = file.size();
        let compressed_size = file.compressed_size();

        let compression_ratio = if size > 0 {
            compressed_size as f64 / size as f64
        } else {
            1.0
        };

        // Check for suspicious compression ratio (potential zip bomb)
        if compression_ratio < SUSPICIOUS_COMPRESSION_RATIO && size > 1024 * 1024 {
            log::warn!(
                "Suspicious compression ratio {:.4} for file '{}' (size: {} bytes)",
                compression_ratio,
                path,
                size
            );
        }

        // Skip files that are too large
        if size > MAX_EXTRACTED_FILE_SIZE {
            log::warn!(
                "Skipping large file '{}' ({} bytes > {} limit)",
                path,
                size,
                MAX_EXTRACTED_FILE_SIZE
            );
            entries.push(ArchiveEntry {
                path,
                file_type: None,
                size,
                compression_ratio,
                skipped: true,
            });
            continue;
        }

        // Check total extraction limit
        if *total_extracted + size > MAX_TOTAL_EXTRACTED_SIZE {
            log::warn!(
                "Total extraction limit reached ({} bytes), skipping remaining entries",
                MAX_TOTAL_EXTRACTED_SIZE
            );
            entries.push(ArchiveEntry {
                path: format!("[LIMIT REACHED] {}", path),
                file_type: None,
                size,
                compression_ratio,
                skipped: true,
            });
            break;
        }

        // Read file contents with bounded reader
        let mut contents = Vec::with_capacity(size.min(MAX_EXTRACTED_FILE_SIZE) as usize);
        let bytes_read = file
            .by_ref()
            .take(MAX_EXTRACTED_FILE_SIZE)
            .read_to_end(&mut contents)
            .map_err(crate::DetectionError::Io)?;

        *total_extracted += bytes_read as u64;

        // Detect file type
        let file_type = FileType::from_bytes(&contents, config).ok();

        // Check if this is also an archive - recurse
        if let Some(ref ft) = file_type {
            if ft.extension == "zip" && current_depth + 1 < max_depth {
                // Recursively scan nested archive with shared extraction limit
                let nested = scan_zip_with_limits(
                    &contents,
                    max_depth,
                    config,
                    current_depth + 1,
                    total_extracted,
                )?;
                for nested_entry in nested {
                    entries.push(ArchiveEntry {
                        path: format!("{}/{}", path, nested_entry.path),
                        file_type: nested_entry.file_type,
                        size: nested_entry.size,
                        compression_ratio: nested_entry.compression_ratio,
                        skipped: nested_entry.skipped,
                    });
                }
            }
        }

        entries.push(ArchiveEntry {
            path,
            file_type,
            size,
            compression_ratio,
            skipped: false,
        });
    }

    // Log if we hit the entry limit
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        log::warn!(
            "Archive has {} entries, only processed first {}",
            archive.len(),
            MAX_ARCHIVE_ENTRIES
        );
    }

    Ok(entries)
}

/// Detect potential zip bombs based on compression ratio
///
/// Returns `true` if the archive appears to be a potential zip bomb based on:
/// - Total uncompressed size > 1GB
/// - Average compression ratio < 5%
pub fn detect_zip_bomb(entries: &[ArchiveEntry]) -> bool {
    if entries.is_empty() {
        return false;
    }

    let total_uncompressed: u64 = entries.iter().map(|e| e.size).sum();
    let avg_compression_ratio: f64 =
        entries.iter().map(|e| e.compression_ratio).sum::<f64>() / entries.len() as f64;

    // Suspicious if total size > 1GB and compression ratio < 0.05
    total_uncompressed > 1_000_000_000 && avg_compression_ratio < 0.05
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_bomb_detection() {
        let entries = vec![ArchiveEntry {
            path: "large.txt".to_string(),
            file_type: None,
            size: 2_000_000_000,
            compression_ratio: 0.01,
            skipped: false,
        }];

        assert!(detect_zip_bomb(&entries));
    }

    #[test]
    fn test_zip_bomb_detection_empty() {
        let entries: Vec<ArchiveEntry> = vec![];
        assert!(!detect_zip_bomb(&entries));
    }

    #[test]
    fn test_zip_bomb_detection_normal() {
        let entries = vec![ArchiveEntry {
            path: "normal.txt".to_string(),
            file_type: None,
            size: 1_000_000, // 1MB
            compression_ratio: 0.5,
            skipped: false,
        }];

        assert!(!detect_zip_bomb(&entries));
    }

    #[test]
    fn test_max_constants() {
        // Ensure constants are reasonable
        assert!(MAX_EXTRACTED_FILE_SIZE > 0);
        assert!(MAX_TOTAL_EXTRACTED_SIZE > MAX_EXTRACTED_FILE_SIZE);
        assert!(MAX_ARCHIVE_ENTRIES > 0);
        assert!(SUSPICIOUS_COMPRESSION_RATIO > 0.0);
        assert!(SUSPICIOUS_COMPRESSION_RATIO < 1.0);
    }
}
