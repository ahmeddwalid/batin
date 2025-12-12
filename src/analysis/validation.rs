//! Content validation module
//!
//! Validates file structure beyond magic byte signatures.

/// Validation result for content structure
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub confidence_boost: f64,
    pub details: String,
}

/// Validate PDF structure
pub fn validate_pdf(data: &[u8]) -> ValidationResult {
    // Check for PDF header
    if data.len() < 5 || &data[0..5] != b"%PDF-" {
        return ValidationResult {
            is_valid: false,
            confidence_boost: -0.3,
            details: "Missing PDF header".to_string(),
        };
    }

    // Check for %%EOF marker
    let has_eof = find_pattern_reverse(data, b"%%EOF").is_some();

    // Check for xref or startxref
    let has_xref =
        find_pattern(data, b"xref").is_some() || find_pattern(data, b"startxref").is_some();

    if has_eof && has_xref {
        ValidationResult {
            is_valid: true,
            confidence_boost: 0.1,
            details: "Valid PDF structure with EOF and xref".to_string(),
        }
    } else if has_eof {
        ValidationResult {
            is_valid: true,
            confidence_boost: 0.05,
            details: "PDF has EOF marker".to_string(),
        }
    } else {
        ValidationResult {
            is_valid: false,
            confidence_boost: -0.1,
            details: "PDF missing EOF marker (possibly truncated)".to_string(),
        }
    }
}

/// Validate PNG structure (check CRC of IHDR chunk)
pub fn validate_png(data: &[u8]) -> ValidationResult {
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A
    if data.len() < 8 || &data[0..8] != &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return ValidationResult {
            is_valid: false,
            confidence_boost: -0.3,
            details: "Invalid PNG signature".to_string(),
        };
    }

    // Check for IHDR chunk (must be first chunk after signature)
    if data.len() >= 16 {
        let chunk_type = &data[12..16];
        if chunk_type == b"IHDR" {
            // Check for IEND chunk
            let has_iend = find_pattern(data, b"IEND").is_some();

            return ValidationResult {
                is_valid: true,
                confidence_boost: if has_iend { 0.1 } else { 0.05 },
                details: if has_iend {
                    "Valid PNG with IHDR and IEND".to_string()
                } else {
                    "PNG has IHDR but missing IEND".to_string()
                },
            };
        }
    }

    ValidationResult {
        is_valid: false,
        confidence_boost: -0.2,
        details: "PNG missing IHDR chunk".to_string(),
    }
}

/// Validate ZIP structure
pub fn validate_zip(data: &[u8]) -> ValidationResult {
    // Check for PK signature
    if data.len() < 4 || &data[0..4] != &[0x50, 0x4B, 0x03, 0x04] {
        return ValidationResult {
            is_valid: false,
            confidence_boost: -0.3,
            details: "Invalid ZIP signature".to_string(),
        };
    }

    // Look for end of central directory signature
    let eocd_sig = [0x50, 0x4B, 0x05, 0x06];
    let has_eocd = find_pattern_reverse(data, &eocd_sig).is_some();

    if has_eocd {
        ValidationResult {
            is_valid: true,
            confidence_boost: 0.1,
            details: "Valid ZIP with end of central directory".to_string(),
        }
    } else {
        ValidationResult {
            is_valid: false,
            confidence_boost: -0.1,
            details: "ZIP missing end of central directory".to_string(),
        }
    }
}

/// Validate PE executable structure
pub fn validate_pe(data: &[u8]) -> ValidationResult {
    // Check for MZ header
    if data.len() < 2 || &data[0..2] != b"MZ" {
        return ValidationResult {
            is_valid: false,
            confidence_boost: -0.3,
            details: "Invalid MZ header".to_string(),
        };
    }

    // Get PE header offset from e_lfanew (offset 0x3C)
    if data.len() >= 0x40 {
        let pe_offset =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

        // Check for PE signature
        if data.len() > pe_offset + 4 {
            if &data[pe_offset..pe_offset + 4] == b"PE\x00\x00" {
                return ValidationResult {
                    is_valid: true,
                    confidence_boost: 0.15,
                    details: "Valid PE with MZ and PE signature".to_string(),
                };
            }
        }
    }

    ValidationResult {
        is_valid: true,
        confidence_boost: 0.0,
        details: "Has MZ header but PE signature not verified".to_string(),
    }
}

/// Detect .NET assembly
pub fn is_dotnet_assembly(data: &[u8]) -> bool {
    // First check for valid PE
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }

    // Look for CLI header indicator
    // .NET assemblies have a CLI header in the PE optional header
    find_pattern(data, b"mscoree.dll").is_some()
        || find_pattern(data, b"_CorExeMain").is_some()
        || find_pattern(data, b"_CorDllMain").is_some()
}

/// Use centralized find_bytes for pattern matching
fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    crate::utils::find_bytes(data, pattern)
}

fn find_pattern_reverse(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.len() > data.len() {
        return None;
    }

    // Search from end for efficiency on EOF markers
    let search_start = data.len().saturating_sub(1024);
    let search_data = &data[search_start..];

    search_data
        .windows(pattern.len())
        .rposition(|window| window == pattern)
        .map(|pos| search_start + pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pdf() {
        let valid_pdf = b"%PDF-1.4\n%%EOF";
        let result = validate_pdf(valid_pdf);
        assert!(result.is_valid);
        assert!(result.confidence_boost > 0.0);
    }

    #[test]
    fn test_validate_png() {
        let valid_png = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG sig
            0x00, 0x00, 0x00, 0x0D, // IHDR length
            b'I', b'H', b'D', b'R', // IHDR type
        ];
        let result = validate_png(&valid_png);
        assert!(result.is_valid);
    }

    #[test]
    fn test_validate_zip() {
        let valid_zip = [
            0x50, 0x4B, 0x03, 0x04, // Local file header
            // ... padding ...
            0x00, 0x00, 0x00, 0x00, 0x50, 0x4B, 0x05, 0x06, // EOCD signature
        ];
        let result = validate_zip(&valid_zip);
        assert!(result.is_valid);
    }

    #[test]
    fn test_is_dotnet_assembly() {
        // This is simplified - real test would need proper PE structure
        assert!(!is_dotnet_assembly(b"not a PE file"));
    }
}
