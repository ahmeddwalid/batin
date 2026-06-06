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

/// Validate PNG structure, verifying each chunk's CRC-32.
///
/// Walks the PNG chunk stream and checks the trailing CRC of every chunk
/// against a recomputed CRC over `type + data`. A CRC mismatch means the file
/// has a valid PNG signature but corrupt/tampered content, surfaced as a
/// distinct, low-confidence result.
pub fn validate_png(data: &[u8]) -> ValidationResult {
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A
    if data.len() < 8 || &data[0..8] != &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return ValidationResult {
            is_valid: false,
            confidence_boost: -0.3,
            details: "Invalid PNG signature".to_string(),
        };
    }

    // First chunk after the signature must be IHDR.
    if data.len() < 16 || &data[12..16] != b"IHDR" {
        return ValidationResult {
            is_valid: false,
            confidence_boost: -0.2,
            details: "PNG missing IHDR chunk".to_string(),
        };
    }

    // Walk chunks: [len:4][type:4][data:len][crc:4]; verify each CRC.
    let mut pos = 8usize;
    let mut checked = 0usize;
    let mut saw_iend = false;
    let mut truncated = false;

    while pos + 8 <= data.len() {
        let len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let type_start = pos + 4;
        let data_start = type_start + 4;
        let crc_start = data_start + len;
        let crc_end = crc_start + 4;
        if crc_end > data.len() {
            truncated = true;
            break;
        }

        let chunk_type = &data[type_start..type_start + 4];
        let stored_crc = u32::from_be_bytes([
            data[crc_start],
            data[crc_start + 1],
            data[crc_start + 2],
            data[crc_start + 3],
        ]);
        // CRC covers chunk type + chunk data.
        let computed = crate::utils::crc32(&data[type_start..crc_start]);
        if computed != stored_crc {
            return ValidationResult {
                is_valid: false,
                confidence_boost: -0.25,
                details: format!(
                    "PNG chunk '{}' CRC mismatch (corrupt or tampered)",
                    String::from_utf8_lossy(chunk_type)
                ),
            };
        }

        checked += 1;
        if chunk_type == b"IEND" {
            saw_iend = true;
            break;
        }
        pos = crc_end;
    }

    if saw_iend {
        ValidationResult {
            is_valid: true,
            confidence_boost: 0.15,
            details: format!("Valid PNG: {checked} chunks CRC-verified, IEND present"),
        }
    } else if truncated {
        ValidationResult {
            is_valid: false,
            confidence_boost: -0.1,
            details: format!("PNG truncated after {checked} valid chunk(s)"),
        }
    } else {
        ValidationResult {
            is_valid: true,
            confidence_boost: 0.05,
            details: format!("PNG: {checked} chunks CRC-verified but IEND missing"),
        }
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

    /// Build a minimal CRC-valid PNG (1x1 grayscale) with IHDR + IEND.
    fn build_png() -> Vec<u8> {
        fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            let mut crc_input = kind.to_vec();
            crc_input.extend_from_slice(data);
            out.extend_from_slice(kind);
            out.extend_from_slice(data);
            out.extend_from_slice(&crate::utils::crc32(&crc_input).to_be_bytes());
        }
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let ihdr = [
            0x00, 0x00, 0x00, 0x01, // width 1
            0x00, 0x00, 0x00, 0x01, // height 1
            0x08, 0x00, 0x00, 0x00, 0x00, // bit depth, color, compression, filter, interlace
        ];
        chunk(&mut png, b"IHDR", &ihdr);
        chunk(&mut png, b"IEND", &[]);
        png
    }

    #[test]
    fn test_validate_png_valid_crc() {
        let png = build_png();
        let result = validate_png(&png);
        assert!(result.is_valid, "{}", result.details);
        assert!(result.confidence_boost > 0.0);
        assert!(result.details.contains("CRC-verified"));
    }

    #[test]
    fn test_validate_png_detects_crc_corruption() {
        let mut png = build_png();
        // Flip a byte inside the IHDR data (offset 16 is start of IHDR data).
        png[16] ^= 0xFF;
        let result = validate_png(&png);
        assert!(!result.is_valid);
        assert!(result.details.contains("CRC mismatch"));
        assert!(result.confidence_boost < 0.0);
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
