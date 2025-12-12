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
            if signature.mime_type.contains("msword") || signature.mime_type.contains("ms-excel") {
                threats.extend(detect_macros(data));
            }

            // Check for PDF JavaScript
            if signature.mime_type == "application/pdf" {
                threats.extend(detect_pdf_javascript(data));
            }
        }
        FileCategory::Archive => {
            // Check for executables in archives
            threats.extend(detect_executable_in_archive(data));
        }
        _ => {}
    }

    Ok(threats)
}

fn detect_macros(data: &[u8]) -> Vec<EmbeddedThreat> {
    use crate::utils::find_bytes;

    let mut threats = Vec::new();

    // Auto-execute macro markers - these are more dangerous
    let auto_exec_markers: [&[u8]; 4] =
        [b"AutoOpen", b"AutoExec", b"Document_Open", b"Workbook_Open"];

    // Regular VBA macro markers
    let macro_markers: [&[u8]; 3] = [b"VBA", b"_VBA_PROJECT", b"macros/"];

    // Check for auto-execute macros first (Critical severity)
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

    // Check for regular macros (Dangerous severity)
    if threats.is_empty() {
        for marker in &macro_markers {
            if let Some(offset) = find_bytes(data, marker) {
                threats.push(EmbeddedThreat {
                    threat_type: ThreatType::Macro,
                    offset,
                    severity: ThreatLevel::Dangerous,
                    description: "Office macro detected".to_string(),
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

    // Look for /JavaScript or /JS tags
    let js_markers: [&[u8]; 2] = [b"/JavaScript", b"/JS"];

    for marker in &js_markers {
        if let Some(offset) = find_bytes(data, marker) {
            threats.push(EmbeddedThreat {
                threat_type: ThreatType::JavaScript,
                offset,
                severity: ThreatLevel::Suspicious,
                description: "PDF with JavaScript detected".to_string(),
            });
            break;
        }
    }

    threats
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
}
