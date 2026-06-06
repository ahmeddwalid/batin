---
sidebar_position: 4
title: Embedded Module
description: Deep dive into embedded threat detection
---

# Embedded Module Deep Dive

Analysis of `src/detection/embedded.rs` for scanning hidden malicious content.

## Purpose

Detect dangerous content **hidden inside** legitimate-looking files:

- VBA macros in Office documents
- JavaScript in PDFs
- Executables in archives

## Data Structures

```rust
#[derive(Debug, Clone, Serialize)]
pub struct EmbeddedThreat {
    pub threat_type: ThreatType,
    pub offset: usize,
    pub severity: ThreatLevel,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub enum ThreatType {
    Macro,
    JavaScript,
    Executable,
    Script,
    Unknown,
}
```

## Main Scanner

```rust
pub fn scan_embedded_content(
    data: &[u8],
    signature: &FileSignature,
) -> Result<Vec<EmbeddedThreat>> {
    let mut threats = Vec::new();
    
    match signature.category {
        FileCategory::Document => {
            if signature.mime_type.contains("msword") 
                || signature.mime_type.contains("ms-excel") 
            {
                threats.extend(detect_macros(data));
            }
            if signature.mime_type == "application/pdf" {
                threats.extend(detect_pdf_javascript(data));
            }
        }
        FileCategory::Archive => {
            threats.extend(detect_executable_in_archive(data));
        }
        _ => {}
    }
    
    Ok(threats)
}
```

## Macro Detection

### Severity Levels

| Marker | Severity | Reason |
|--------|----------|--------|
| `AutoOpen` | **Critical** | Runs automatically |
| `AutoExec` | **Critical** | Runs on app start |
| `Document_Open` | **Critical** | Runs on open |
| `VBA` | Dangerous | Requires user action |

### Implementation

```rust
fn detect_macros(data: &[u8]) -> Vec<EmbeddedThreat> {
    let mut threats = Vec::new();
    
    // Auto-execute = Critical
    let auto_exec = [b"AutoOpen", b"AutoExec", b"Document_Open", b"Workbook_Open"];
    for marker in &auto_exec {
        if let Some(offset) = find_bytes(data, marker) {
            threats.push(EmbeddedThreat {
                threat_type: ThreatType::Macro,
                offset,
                severity: ThreatLevel::Critical,
                description: format!("Auto-execute: {}", 
                    String::from_utf8_lossy(marker)),
            });
        }
    }
    
    // Regular macros = Dangerous (only if no auto-exec)
    if threats.is_empty() {
        for marker in [b"VBA", b"_VBA_PROJECT"] {
            if let Some(offset) = find_bytes(data, marker) {
                threats.push(EmbeddedThreat {
                    threat_type: ThreatType::Macro,
                    offset,
                    severity: ThreatLevel::Dangerous,
                    description: "VBA macro detected".to_string(),
                });
                break;
            }
        }
    }
    
    threats
}
```

## PDF JavaScript Detection

```rust
fn detect_pdf_javascript(data: &[u8]) -> Vec<EmbeddedThreat> {
    let mut threats = Vec::new();
    
    for marker in [b"/JavaScript", b"/JS"] {
        if let Some(offset) = find_bytes(data, marker) {
            threats.push(EmbeddedThreat {
                threat_type: ThreatType::JavaScript,
                offset,
                severity: ThreatLevel::Suspicious,
                description: "PDF with JavaScript".to_string(),
            });
            break;
        }
    }
    
    threats
}
```

## Archive Executable Detection

```rust
fn detect_executable_in_archive(data: &[u8]) -> Vec<EmbeddedThreat> {
    let mut threats = Vec::new();
    
    // Look for PE header in archive
    if let Some(offset) = find_bytes(data, &[0x4D, 0x5A]) {
        threats.push(EmbeddedThreat {
            threat_type: ThreatType::Executable,
            offset,
            severity: ThreatLevel::Dangerous,
            description: "Executable in archive".to_string(),
        });
    }
    
    threats
}
```

---

## Integration with Threat Assessment

```rust
// Maximum embedded threat severity escalates file threat level
let final_level = embedded_threats
    .iter()
    .map(|t| t.severity)
    .max()
    .unwrap_or(base_level)
    .max(base_level);
```
