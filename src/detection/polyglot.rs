//! Polyglot file detection module

use super::signatures::SignatureDatabase;
use crate::Result;

/// Detect if file is valid in multiple formats simultaneously
pub fn detect_polyglot(data: &[u8], db: &SignatureDatabase) -> Result<Vec<String>> {
    use crate::utils::find_bytes;

    let mut detected_formats = Vec::new();

    // Check multiple signature locations
    let check_offsets = [0, 512, 1024, 2048];

    for offset in check_offsets {
        if offset >= data.len() {
            break;
        }

        let slice = &data[offset..];
        let matches = db.match_signatures(slice);

        for (sig_idx, _confidence) in matches {
            let sig = &db.signatures[sig_idx];
            let format = sig.extensions[0].clone();

            if !detected_formats.contains(&format) {
                detected_formats.push(format);
            }
        }
    }

    // Look for embedded PE in PDF (common attack)
    if data.len() > 4 && &data[0..4] == b"%PDF" {
        if let Some(pe_pos) = find_bytes(data, &[0x4D, 0x5A]) {
            if pe_pos > 100 {
                detected_formats.push("exe".to_string());
            }
        }
    }

    Ok(detected_formats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyglot_detection() {
        // PDF with embedded executable signature
        let mut polyglot_data = b"%PDF-1.4\n".to_vec();
        polyglot_data.extend_from_slice(&vec![0u8; 200]);
        polyglot_data.extend_from_slice(&[0x4D, 0x5A]); // MZ header

        let db = SignatureDatabase::default();
        let formats = detect_polyglot(&polyglot_data, &db).unwrap();

        assert!(formats.len() > 1, "Should detect multiple formats");
        assert!(formats.contains(&"pdf".to_string()));
        assert!(formats.contains(&"exe".to_string()));
    }

    #[test]
    fn test_single_format_detection() {
        // Regular PNG file header
        let png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

        let db = SignatureDatabase::default();
        let formats = detect_polyglot(&png_data, &db).unwrap();

        assert_eq!(formats.len(), 1, "Should detect only one format");
        assert_eq!(formats[0], "png");
    }

    #[test]
    fn test_find_bytes() {
        use crate::utils::find_bytes;
        let data = b"hello world";
        assert_eq!(find_bytes(data, b"world"), Some(6));
        assert_eq!(find_bytes(data, b"xyz"), None);
        assert_eq!(find_bytes(data, b"hello"), Some(0));
    }

    #[test]
    fn test_empty_data() {
        let db = SignatureDatabase::default();
        let formats = detect_polyglot(&[], &db).unwrap();
        assert!(formats.is_empty());
    }
}
