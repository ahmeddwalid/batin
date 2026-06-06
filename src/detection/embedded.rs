//! Embedded content detection module

use super::signatures::{FileCategory, FileSignature};
use crate::{Result, ThreatLevel};

#[derive(Debug, Clone, serde::Serialize)]
pub struct EmbeddedThreat {
    pub threat_type: ThreatType,
    pub offset: usize,
    pub severity: ThreatLevel,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum ThreatType {
    Macro,
    JavaScript,
    Executable,
    Script,
    Unknown,
}

/// Scan for embedded dangerous content
pub fn scan_embedded_content(
    data: &[u8],
    signature: &FileSignature,
) -> Result<Vec<EmbeddedThreat>> {
    let mut threats = Vec::new();

    match signature.category {
        FileCategory::Document => {
            // Check for Office macros
            if signature.mime_type.contains("msword")
                || signature.mime_type.contains("ms-excel")
                || signature.mime_type.contains("officedocument")
                || signature.mime_type.contains("opendocument")
            {
                threats.extend(detect_macros(data));
            }

            // Check for PDF JavaScript / auto-actions
            if signature.mime_type == "application/pdf" {
                threats.extend(detect_pdf_javascript(data));
            }

            // Encoded payloads can hide in any document.
            threats.extend(detect_encoded_executables(data));
        }
        FileCategory::Archive => {
            // Check for executables in archives
            threats.extend(detect_executable_in_archive(data));
            threats.extend(detect_encoded_executables(data));
        }
        FileCategory::Text => {
            // Droppers often stash base64/XOR-encoded payloads in text/scripts.
            threats.extend(detect_encoded_executables(data));
        }
        _ => {}
    }

    Ok(threats)
}

fn detect_macros(data: &[u8]) -> Vec<EmbeddedThreat> {
    use crate::utils::find_bytes;

    let mut threats = Vec::new();

    // Auto-execute macro markers - these are more dangerous
    let auto_exec_markers: [&[u8]; 6] = [
        b"AutoOpen",
        b"AutoExec",
        b"AutoClose",
        b"Document_Open",
        b"Workbook_Open",
        b"Auto_Open",
    ];

    // Regular VBA macro markers
    let macro_markers: [&[u8]; 4] = [b"_VBA_PROJECT", b"vbaProject.bin", b"macros/", b"VBA"];

    // Report every auto-execute marker found (Critical severity).
    for marker in &auto_exec_markers {
        if let Some(offset) = find_bytes(data, marker) {
            threats.push(EmbeddedThreat {
                threat_type: ThreatType::Macro,
                offset,
                severity: ThreatLevel::Critical,
                description: format!(
                    "Auto-execute macro detected: {}",
                    String::from_utf8_lossy(marker)
                ),
            });
        }
    }

    // Report regular macro markers (Dangerous). Only if no auto-exec already
    // covers it, to avoid double-counting the same VBA project.
    if threats.is_empty() {
        for marker in &macro_markers {
            if let Some(offset) = find_bytes(data, marker) {
                threats.push(EmbeddedThreat {
                    threat_type: ThreatType::Macro,
                    offset,
                    severity: ThreatLevel::Dangerous,
                    description: format!(
                        "Office macro detected: {}",
                        String::from_utf8_lossy(marker)
                    ),
                });
                break;
            }
        }
    }

    threats
}

fn detect_pdf_javascript(data: &[u8]) -> Vec<EmbeddedThreat> {
    use crate::utils::find_bytes;

    let mut threats = Vec::new();

    // JavaScript tags (Suspicious).
    for marker in [b"/JavaScript".as_slice(), b"/JS".as_slice()] {
        if let Some(offset) = find_bytes(data, marker) {
            threats.push(EmbeddedThreat {
                threat_type: ThreatType::JavaScript,
                offset,
                severity: ThreatLevel::Suspicious,
                description: format!("PDF JavaScript tag: {}", String::from_utf8_lossy(marker)),
            });
            break;
        }
    }

    // Auto-actions and launchers raise severity (Dangerous): these run code on open.
    let action_markers: [(&[u8], &str); 4] = [
        (
            b"/OpenAction",
            "PDF auto-runs an action on open (/OpenAction)",
        ),
        (b"/AA", "PDF additional-actions trigger (/AA)"),
        (b"/Launch", "PDF launches an external program (/Launch)"),
        (
            b"/EmbeddedFile",
            "PDF contains an embedded file (/EmbeddedFile)",
        ),
    ];
    for (marker, desc) in &action_markers {
        if let Some(offset) = find_bytes(data, marker) {
            threats.push(EmbeddedThreat {
                threat_type: ThreatType::JavaScript,
                offset,
                severity: ThreatLevel::Dangerous,
                description: desc.to_string(),
            });
        }
    }

    threats
}

/// Detect base64- or single-byte-XOR-encoded executables hidden in content.
///
/// Catches a common evasion where a PE payload is stored encoded so its raw
/// `MZ` magic never appears in the file.
fn detect_encoded_executables(data: &[u8]) -> Vec<EmbeddedThreat> {
    use crate::utils::find_bytes;

    let mut threats = Vec::new();

    // Base64 prefixes for common MZ headers, and base64 of the PE DOS stub string.
    let base64_markers: [(&[u8], &str); 5] = [
        (b"TVqQ", "Base64-encoded executable (MZ header)"),
        (b"TVpB", "Base64-encoded executable (MZP header)"),
        (b"TVoA", "Base64-encoded executable (MZ header)"),
        (b"TVqA", "Base64-encoded executable (MZ header)"),
        (
            b"VGhpcyBwcm9ncmFt",
            "Base64-encoded PE DOS stub ('This program...')",
        ),
    ];
    for (marker, desc) in &base64_markers {
        if let Some(offset) = find_bytes(data, marker) {
            threats.push(EmbeddedThreat {
                threat_type: ThreatType::Executable,
                offset,
                severity: ThreatLevel::Dangerous,
                description: desc.to_string(),
            });
            break;
        }
    }

    // Single-byte XOR-encoded PE: look for the DOS stub string under each key.
    if let Some((offset, key)) = detect_xor_dos_stub(data) {
        threats.push(EmbeddedThreat {
            threat_type: ThreatType::Executable,
            offset,
            severity: ThreatLevel::Dangerous,
            description: format!("XOR-encoded executable (single-byte key 0x{key:02x})"),
        });
    }

    threats
}

/// The PE DOS stub message, present in virtually every PE file.
const DOS_STUB: &[u8] = b"This program cannot be run in DOS mode";

/// Brute-force single-byte XOR keys to find an obfuscated PE DOS stub.
///
/// Bounded to the first 64KiB to keep cost predictable. Returns the offset and
/// key on the first match.
fn detect_xor_dos_stub(data: &[u8]) -> Option<(usize, u8)> {
    const SCAN_LIMIT: usize = 64 * 1024;
    let window = &data[..data.len().min(SCAN_LIMIT)];
    if window.len() < DOS_STUB.len() {
        return None;
    }

    // Key 0 is plaintext; skip it (handled elsewhere) and scan 1..=255.
    let first = DOS_STUB[0];
    for key in 1u8..=255 {
        let target0 = first ^ key;
        // Quick filter: find candidate positions of the first encoded byte.
        for i in 0..=window.len() - DOS_STUB.len() {
            if window[i] != target0 {
                continue;
            }
            if DOS_STUB
                .iter()
                .enumerate()
                .all(|(j, &b)| window[i + j] == b ^ key)
            {
                return Some((i, key));
            }
        }
    }
    None
}

fn detect_executable_in_archive(data: &[u8]) -> Vec<EmbeddedThreat> {
    use crate::utils::find_bytes;

    let mut threats = Vec::new();

    // Look for PE header (MZ) in ZIP content
    if let Some(offset) = find_bytes(data, &[0x4D, 0x5A]) {
        threats.push(EmbeddedThreat {
            threat_type: ThreatType::Executable,
            offset,
            severity: crate::ThreatLevel::Dangerous,
            description: "Executable file in archive".to_string(),
        });
    }

    threats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_macros() {
        let data_with_macro = b"some content VBA more content";
        let threats = detect_macros(data_with_macro);
        assert!(!threats.is_empty(), "Should detect VBA macro");
        assert!(matches!(threats[0].threat_type, ThreatType::Macro));
    }

    #[test]
    fn test_detect_macros_none() {
        let clean_data = b"just regular document content";
        let threats = detect_macros(clean_data);
        assert!(threats.is_empty(), "Should not detect macros in clean data");
    }

    #[test]
    fn test_detect_pdf_javascript() {
        let pdf_with_js = b"%PDF-1.4 /JavaScript action here";
        let threats = detect_pdf_javascript(pdf_with_js);
        assert!(!threats.is_empty(), "Should detect JavaScript in PDF");
        assert!(matches!(threats[0].threat_type, ThreatType::JavaScript));
    }

    #[test]
    fn test_detect_executable_in_archive() {
        let archive_with_exe = b"PK\x03\x04 some content MZ more content";
        let threats = detect_executable_in_archive(archive_with_exe);
        assert!(!threats.is_empty(), "Should detect executable in archive");
    }

    #[test]
    fn test_find_bytes() {
        use crate::utils::find_bytes;
        assert_eq!(find_bytes(b"hello VBA world", b"VBA"), Some(6));
        assert_eq!(find_bytes(b"clean content", b"VBA"), None);
    }

    #[test]
    fn test_detect_macros_reports_all_auto_exec() {
        let data = b"junk AutoOpen junk Document_Open junk";
        let threats = detect_macros(data);
        assert_eq!(threats.len(), 2);
        assert!(threats
            .iter()
            .all(|t| matches!(t.severity, ThreatLevel::Critical)));
    }

    #[test]
    fn test_detect_base64_executable() {
        let data = b"var payload = 'TVqQAAMAAAAEAAAA//8AALg=';";
        let threats = detect_encoded_executables(data);
        assert!(threats
            .iter()
            .any(|t| matches!(t.threat_type, ThreatType::Executable)));
    }

    #[test]
    fn test_detect_xor_encoded_executable() {
        // Encode the DOS stub with a single-byte XOR key and embed it.
        let key = 0x5Au8;
        let mut data = vec![0u8; 32];
        data.extend(DOS_STUB.iter().map(|b| b ^ key));
        data.extend_from_slice(b"trailing");

        let found = detect_xor_dos_stub(&data);
        assert_eq!(found, Some((32, key)));

        let threats = detect_encoded_executables(&data);
        assert!(threats
            .iter()
            .any(|t| t.description.contains("XOR-encoded")));
    }

    #[test]
    fn test_no_false_positive_on_clean_text() {
        let data = b"This is a perfectly ordinary sentence with no payloads.";
        assert!(detect_encoded_executables(data).is_empty());
    }

    #[test]
    fn test_pdf_auto_action_is_dangerous() {
        let data = b"%PDF-1.7 /OpenAction << /S /JavaScript >>";
        let threats = detect_pdf_javascript(data);
        assert!(threats
            .iter()
            .any(|t| matches!(t.severity, ThreatLevel::Dangerous)));
    }
}
