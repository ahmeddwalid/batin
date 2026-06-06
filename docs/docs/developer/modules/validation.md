---
sidebar_position: 5
title: Validation Module
description: Deep dive into file structure validation
---

# Validation Module Deep Dive

Analysis of `src/analysis/validation.rs` for structural validation beyond magic bytes.

## Purpose

Validate file **internal structure** to:

- Increase detection confidence
- Detect corrupted/truncated files
- Identify malformed content

## Validation Results

```rust
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,        // Structure is valid
    pub confidence_boost: f64, // Adjust detection confidence
    pub details: String,       // Human-readable explanation
}
```

## PDF Validation

```rust
pub fn validate_pdf(data: &[u8]) -> ValidationResult {
    // 1. Check header
    if &data[0..5] != b"%PDF-" {
        return ValidationResult {
            is_valid: false,
            confidence_boost: -0.3,
            details: "Missing PDF header".to_string(),
        };
    }
    
    // 2. Check EOF marker
    let has_eof = find_pattern_reverse(data, b"%%EOF").is_some();
    
    // 3. Check xref/startxref
    let has_xref = find_pattern(data, b"xref").is_some()
                || find_pattern(data, b"startxref").is_some();
    
    if has_eof && has_xref {
        ValidationResult {
            is_valid: true,
            confidence_boost: 0.1,
            details: "Valid PDF with EOF and xref".to_string(),
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
            details: "PDF missing EOF (possibly truncated)".to_string(),
        }
    }
}
```

## PNG Validation

```rust
pub fn validate_png(data: &[u8]) -> ValidationResult {
    // Check PNG signature
    let png_sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 8 || &data[0..8] != &png_sig {
        return ValidationResult {
            is_valid: false,
            confidence_boost: -0.3,
            details: "Invalid PNG signature".to_string(),
        };
    }
    
    // Check IHDR chunk (must be first)
    if data.len() >= 16 && &data[12..16] == b"IHDR" {
        let has_iend = find_pattern(data, b"IEND").is_some();
        return ValidationResult {
            is_valid: true,
            confidence_boost: if has_iend { 0.1 } else { 0.05 },
            details: if has_iend { 
                "Valid PNG with IHDR and IEND" 
            } else { 
                "PNG has IHDR but missing IEND" 
            }.to_string(),
        };
    }
    
    ValidationResult {
        is_valid: false,
        confidence_boost: -0.2,
        details: "PNG missing IHDR chunk".to_string(),
    }
}
```

## PE Executable Validation

```rust
pub fn validate_pe(data: &[u8]) -> ValidationResult {
    // Check MZ header
    if data.len() < 2 || &data[0..2] != b"MZ" {
        return ValidationResult {
            is_valid: false,
            confidence_boost: -0.3,
            details: "Invalid MZ header".to_string(),
        };
    }
    
    // Get PE header offset from e_lfanew
    if data.len() >= 0x40 {
        let pe_offset = u32::from_le_bytes([
            data[0x3C], data[0x3D], data[0x3E], data[0x3F]
        ]) as usize;
        
        // Check PE signature
        if data.len() > pe_offset + 4 
           && &data[pe_offset..pe_offset + 4] == b"PE\x00\x00" 
        {
            return ValidationResult {
                is_valid: true,
                confidence_boost: 0.15,
                details: "Valid PE with MZ and PE signature".to_string(),
            };
        }
    }
    
    ValidationResult {
        is_valid: true,
        confidence_boost: 0.0,
        details: "Has MZ but PE signature not verified".to_string(),
    }
}
```

## .NET Detection

```rust
pub fn is_dotnet_assembly(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }
    
    // Look for CLI header indicators
    find_pattern(data, b"mscoree.dll").is_some()
        || find_pattern(data, b"_CorExeMain").is_some()
        || find_pattern(data, b"_CorDllMain").is_some()
}
```

## Efficient Reverse Search

```rust
fn find_pattern_reverse(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.len() > data.len() { return None; }
    
    // Only search last 1KB for efficiency
    let search_start = data.len().saturating_sub(1024);
    let search_data = &data[search_start..];
    
    search_data
        .windows(pattern.len())
        .rposition(|window| window == pattern)
        .map(|pos| search_start + pos)
}
```

---

## Confidence Adjustment

| Validation Result | Confidence Change |
|-------------------|------------------|
| Full validation passed | +0.10 to +0.15 |
| Partial validation | +0.05 |
| Validation failed | -0.10 to -0.30 |
