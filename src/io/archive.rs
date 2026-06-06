//! Archive recursion module
//!
//! Scans inside archive files (ZIP, TAR, TAR.GZ) recursively to detect nested
//! threats. Includes protection against zip bombs and memory exhaustion.

use crate::FileType;
#[cfg(feature = "archive")]
use crate::{DetectionConfig, Result};
#[cfg(feature = "archive")]
use flate2::read::GzDecoder;
#[cfg(feature = "archive")]
use std::io::{Cursor, Read};
#[cfg(feature = "archive")]
use tar::Archive as TarArchive;
#[cfg(feature = "archive")]
use zip::ZipArchive;

/// Default maximum size of a single extracted file (50MB)
const DEFAULT_MAX_EXTRACTED_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Default maximum total extracted size per archive (500MB)
const DEFAULT_MAX_TOTAL_EXTRACTED_SIZE: u64 = 500 * 1024 * 1024;

/// Default maximum number of entries to process in an archive
const DEFAULT_MAX_ARCHIVE_ENTRIES: usize = 10_000;

/// Default minimum compression ratio that indicates a potential bomb (1%)
const DEFAULT_SUSPICIOUS_COMPRESSION_RATIO: f64 = 0.01;

/// Tunable limits governing archive extraction.
///
/// Defaults are conservative for fast triage; forensics workflows can raise
/// them to scan larger or more deeply nested archives.
#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    /// Maximum bytes to extract from any single entry.
    pub max_extracted_file_size: u64,
    /// Maximum total bytes to extract across the whole (recursive) archive.
    pub max_total_extracted_size: u64,
    /// Maximum number of entries to process per archive container.
    pub max_entries: usize,
    /// Compression ratios below this (for entries > 1MB) are flagged as suspicious.
    pub suspicious_compression_ratio: f64,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            max_extracted_file_size: DEFAULT_MAX_EXTRACTED_FILE_SIZE,
            max_total_extracted_size: DEFAULT_MAX_TOTAL_EXTRACTED_SIZE,
            max_entries: DEFAULT_MAX_ARCHIVE_ENTRIES,
            suspicious_compression_ratio: DEFAULT_SUSPICIOUS_COMPRESSION_RATIO,
        }
    }
}

/// Container formats Batin can recurse into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    Zip,
    Tar,
    Gzip,
    Unknown,
}

/// Whether `data` is a container Batin can recurse into (ZIP, TAR, or gzip).
///
/// Decided from magic bytes, so ZIP-derived formats (DOCX, JAR, APK, …) and
/// `.tar.gz` are all recognised regardless of their semantic file extension.
pub fn is_recursible_archive(data: &[u8]) -> bool {
    detect_archive_kind(data) != ArchiveKind::Unknown
}

/// Identify the archive container type from leading bytes.
fn detect_archive_kind(data: &[u8]) -> ArchiveKind {
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return ArchiveKind::Zip;
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        return ArchiveKind::Gzip;
    }
    // TAR has the "ustar" magic at offset 257.
    if data.len() > 262 && &data[257..262] == b"ustar" {
        return ArchiveKind::Tar;
    }
    ArchiveKind::Unknown
}

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
#[cfg(feature = "archive")]
pub fn scan_archive(
    data: &[u8],
    max_depth: usize,
    config: &DetectionConfig,
) -> Result<Vec<ArchiveEntry>> {
    scan_archive_with_config(data, max_depth, config, &ArchiveConfig::default())
}

/// Scan archive contents recursively with explicit extraction limits.
///
/// Like [`scan_archive`] but lets callers tune [`ArchiveConfig`] for forensics
/// (deeper/larger) or fast-triage (tighter) workloads. Dispatches on the
/// detected container type (ZIP, TAR, or gzip/tar.gz).
#[cfg(feature = "archive")]
pub fn scan_archive_with_config(
    data: &[u8],
    max_depth: usize,
    config: &DetectionConfig,
    archive_config: &ArchiveConfig,
) -> Result<Vec<ArchiveEntry>> {
    let mut total_extracted = 0;
    scan_dispatch(
        data,
        max_depth,
        config,
        archive_config,
        0,
        &mut total_extracted,
    )
}

/// Route to the right scanner based on the container format.
#[cfg(feature = "archive")]
fn scan_dispatch(
    data: &[u8],
    max_depth: usize,
    config: &DetectionConfig,
    ac: &ArchiveConfig,
    current_depth: usize,
    total_extracted: &mut u64,
) -> Result<Vec<ArchiveEntry>> {
    if current_depth >= max_depth {
        return Ok(Vec::new());
    }

    match detect_archive_kind(data) {
        ArchiveKind::Zip => {
            scan_zip_with_limits(data, max_depth, config, ac, current_depth, total_extracted)
        }
        ArchiveKind::Tar => scan_tar(data, max_depth, config, ac, current_depth, total_extracted),
        ArchiveKind::Gzip => scan_gzip(data, max_depth, config, ac, current_depth, total_extracted),
        // Fall back to attempting a ZIP read (covers ZIP-derived formats whose
        // magic differs but which are valid ZIP containers).
        ArchiveKind::Unknown => {
            scan_zip_with_limits(data, max_depth, config, ac, current_depth, total_extracted)
        }
    }
}

/// Recurse into an extracted entry if it is itself a supported archive.
#[cfg(feature = "archive")]
fn maybe_recurse_entry(
    contents: &[u8],
    parent_path: &str,
    max_depth: usize,
    config: &DetectionConfig,
    ac: &ArchiveConfig,
    current_depth: usize,
    total_extracted: &mut u64,
    entries: &mut Vec<ArchiveEntry>,
) {
    if current_depth + 1 >= max_depth {
        return;
    }
    if detect_archive_kind(contents) == ArchiveKind::Unknown {
        return;
    }
    if let Ok(nested) = scan_dispatch(
        contents,
        max_depth,
        config,
        ac,
        current_depth + 1,
        total_extracted,
    ) {
        for nested_entry in nested {
            entries.push(ArchiveEntry {
                path: format!("{}/{}", parent_path, nested_entry.path),
                file_type: nested_entry.file_type,
                size: nested_entry.size,
                compression_ratio: nested_entry.compression_ratio,
                skipped: nested_entry.skipped,
            });
        }
    }
}

/// Internal function that tracks total extracted size across recursive calls
#[cfg(feature = "archive")]
fn scan_zip_with_limits(
    data: &[u8],
    max_depth: usize,
    config: &DetectionConfig,
    ac: &ArchiveConfig,
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
    let entry_count = archive.len().min(ac.max_entries);

    // Early zip bomb detection: check total claimed size before extraction
    // We calculate this by iterating through entries and summing claimed sizes
    let mut total_claimed_size: u64 = 0;
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index(i) {
            total_claimed_size += file.size();
        }
    }

    if total_claimed_size > ac.max_total_extracted_size {
        log::warn!(
            "Archive claims {} bytes uncompressed, exceeds limit of {} bytes",
            total_claimed_size,
            ac.max_total_extracted_size
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
        if compression_ratio < ac.suspicious_compression_ratio && size > 1024 * 1024 {
            log::warn!(
                "Suspicious compression ratio {:.4} for file '{}' (size: {} bytes)",
                compression_ratio,
                path,
                size
            );
        }

        // Skip files that are too large
        if size > ac.max_extracted_file_size {
            log::warn!(
                "Skipping large file '{}' ({} bytes > {} limit)",
                path,
                size,
                ac.max_extracted_file_size
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
        if *total_extracted + size > ac.max_total_extracted_size {
            log::warn!(
                "Total extraction limit reached ({} bytes), skipping remaining entries",
                ac.max_total_extracted_size
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
        let mut contents = Vec::with_capacity(size.min(ac.max_extracted_file_size) as usize);
        let bytes_read = file
            .by_ref()
            .take(ac.max_extracted_file_size)
            .read_to_end(&mut contents)
            .map_err(crate::DetectionError::Io)?;

        *total_extracted += bytes_read as u64;

        // Detect file type
        let file_type = FileType::from_bytes(&contents, config).ok();

        // Recurse into nested archives (zip/tar/gzip) sharing the extraction limit.
        maybe_recurse_entry(
            &contents,
            &path,
            max_depth,
            config,
            ac,
            current_depth,
            total_extracted,
            &mut entries,
        );

        entries.push(ArchiveEntry {
            path,
            file_type,
            size,
            compression_ratio,
            skipped: false,
        });
    }

    // Log if we hit the entry limit
    if archive.len() > ac.max_entries {
        log::warn!(
            "Archive has {} entries, only processed first {}",
            archive.len(),
            ac.max_entries
        );
    }

    Ok(entries)
}

/// Scan an uncompressed TAR container.
#[cfg(feature = "archive")]
fn scan_tar(
    data: &[u8],
    max_depth: usize,
    config: &DetectionConfig,
    ac: &ArchiveConfig,
    current_depth: usize,
    total_extracted: &mut u64,
) -> Result<Vec<ArchiveEntry>> {
    if current_depth >= max_depth {
        return Ok(Vec::new());
    }

    let mut archive = TarArchive::new(Cursor::new(data));
    let tar_entries = archive.entries().map_err(|e| {
        crate::DetectionError::CorruptedStructure(format!("Failed to read TAR: {e}"))
    })?;

    let mut entries = Vec::new();
    let mut processed = 0usize;

    for entry in tar_entries {
        if processed >= ac.max_entries {
            log::warn!(
                "TAR has more than {} entries, stopping early",
                ac.max_entries
            );
            break;
        }
        processed += 1;

        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                log::warn!("Skipping unreadable TAR entry: {e}");
                continue;
            }
        };

        let size = entry.header().size().unwrap_or(0);
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "[unreadable path]".to_string());

        // TAR stores files uncompressed; ratio is meaningful only for the
        // surrounding (gzip) layer, so report 1.0 here.
        let compression_ratio = 1.0;

        if size > ac.max_extracted_file_size {
            log::warn!(
                "Skipping large TAR file '{}' ({} bytes > {} limit)",
                path,
                size,
                ac.max_extracted_file_size
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

        if *total_extracted + size > ac.max_total_extracted_size {
            log::warn!(
                "Total extraction limit reached ({} bytes), skipping remaining TAR entries",
                ac.max_total_extracted_size
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

        let mut contents = Vec::with_capacity(size.min(ac.max_extracted_file_size) as usize);
        let bytes_read = entry
            .by_ref()
            .take(ac.max_extracted_file_size)
            .read_to_end(&mut contents)
            .map_err(crate::DetectionError::Io)?;
        *total_extracted += bytes_read as u64;

        let file_type = FileType::from_bytes(&contents, config).ok();

        maybe_recurse_entry(
            &contents,
            &path,
            max_depth,
            config,
            ac,
            current_depth,
            total_extracted,
            &mut entries,
        );

        entries.push(ArchiveEntry {
            path,
            file_type,
            size,
            compression_ratio,
            skipped: false,
        });
    }

    Ok(entries)
}

/// Scan a gzip stream. Gzip wraps a single member; the common case is `.tar.gz`,
/// in which the decompressed payload is itself a TAR and is scanned recursively.
#[cfg(feature = "archive")]
fn scan_gzip(
    data: &[u8],
    max_depth: usize,
    config: &DetectionConfig,
    ac: &ArchiveConfig,
    current_depth: usize,
    total_extracted: &mut u64,
) -> Result<Vec<ArchiveEntry>> {
    if current_depth >= max_depth {
        return Ok(Vec::new());
    }

    // Decompress, bounding output to the total extraction budget.
    let mut decompressed = Vec::new();
    GzDecoder::new(Cursor::new(data))
        .take(ac.max_total_extracted_size)
        .read_to_end(&mut decompressed)
        .map_err(crate::DetectionError::Io)?;
    *total_extracted += decompressed.len() as u64;

    let compression_ratio = if !decompressed.is_empty() {
        data.len() as f64 / decompressed.len() as f64
    } else {
        1.0
    };

    if compression_ratio < ac.suspicious_compression_ratio && decompressed.len() > 1024 * 1024 {
        log::warn!(
            "Suspicious gzip compression ratio {:.4} ({} -> {} bytes)",
            compression_ratio,
            data.len(),
            decompressed.len()
        );
    }

    // tar.gz: recurse into the inner TAR.
    if detect_archive_kind(&decompressed) == ArchiveKind::Tar {
        return scan_tar(
            &decompressed,
            max_depth,
            config,
            ac,
            current_depth,
            total_extracted,
        );
    }

    // Single-member gzip: report the decompressed payload as one entry.
    let file_type = FileType::from_bytes(&decompressed, config).ok();
    Ok(vec![ArchiveEntry {
        path: "[gzip member]".to_string(),
        file_type,
        size: decompressed.len() as u64,
        compression_ratio,
        skipped: false,
    }])
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

#[cfg(all(test, feature = "archive"))]
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
    fn test_default_archive_config() {
        let ac = ArchiveConfig::default();
        assert!(ac.max_extracted_file_size > 0);
        assert!(ac.max_total_extracted_size > ac.max_extracted_file_size);
        assert!(ac.max_entries > 0);
        assert!(ac.suspicious_compression_ratio > 0.0);
        assert!(ac.suspicious_compression_ratio < 1.0);
    }

    #[test]
    fn test_detect_archive_kind() {
        assert_eq!(detect_archive_kind(b"PK\x03\x04rest"), ArchiveKind::Zip);
        assert_eq!(detect_archive_kind(&[0x1f, 0x8b, 0x08]), ArchiveKind::Gzip);
        assert_eq!(detect_archive_kind(b"not an archive"), ArchiveKind::Unknown);

        let mut tar = vec![0u8; 263];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_archive_kind(&tar), ArchiveKind::Tar);
    }

    #[test]
    fn test_scan_tar_with_embedded_content() {
        // Build a TAR in memory containing a small PNG, then scan it.
        let png = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, b'I', b'H',
            b'D', b'R',
        ];
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(png.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "image.png", &png[..])
            .unwrap();
        let tar_bytes = builder.into_inner().unwrap();

        let config = DetectionConfig::default();
        let entries = scan_archive(&tar_bytes, 3, &config).unwrap();
        assert!(entries.iter().any(|e| e.path == "image.png"));
        let png_entry = entries.iter().find(|e| e.path == "image.png").unwrap();
        assert_eq!(
            png_entry.file_type.as_ref().map(|ft| ft.extension.as_str()),
            Some("png")
        );
    }
}
