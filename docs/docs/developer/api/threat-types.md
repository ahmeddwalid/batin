---
sidebar_position: 4
title: Threat Types API
description: Threat level and embedded threat types
---

# Threat Types API Reference

Types for threat assessment and embedded content detection.

## ThreatLevel

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ThreatLevel {
    /// No threats detected
    Safe,
    
    /// Minor concerns (e.g., executables)
    Suspicious,
    
    /// High risk (packed, polyglot, macros)
    Dangerous,
    
    /// Immediate threat (auto-execute macros)
    Critical,
}
```

### Ordering

Threat levels are ordered for comparison:

```rust
assert!(ThreatLevel::Safe < ThreatLevel::Suspicious);
assert!(ThreatLevel::Suspicious < ThreatLevel::Dangerous);
assert!(ThreatLevel::Dangerous < ThreatLevel::Critical);

// Get maximum
let levels = vec![ThreatLevel::Safe, ThreatLevel::Dangerous];
let max = levels.iter().max().unwrap(); // Dangerous
```

### Usage

```rust
match result.threat_level {
    ThreatLevel::Safe => {
        println!("✓ Safe file");
    }
    ThreatLevel::Suspicious => {
        println!("⚠ Suspicious - review recommended");
    }
    ThreatLevel::Dangerous => {
        println!("⚠ Dangerous - quarantine recommended");
        quarantine_file(&path);
    }
    ThreatLevel::Critical => {
        println!("✖ Critical threat - blocking");
        block_file(&path);
        alert_security();
    }
}
```

---

## EmbeddedThreat

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct EmbeddedThreat {
    /// Type of embedded threat
    pub threat_type: ThreatType,
    
    /// Byte offset where threat was found
    pub offset: usize,
    
    /// Severity of this specific threat
    pub severity: ThreatLevel,
    
    /// Human-readable description
    pub description: String,
}
```

### Usage

```rust
for threat in &result.embedded_threats {
    println!("Found {:?} at offset {}", threat.threat_type, threat.offset);
    println!("  Severity: {:?}", threat.severity);
    println!("  Details: {}", threat.description);
}
```

---

## ThreatType

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub enum ThreatType {
    /// VBA macros in Office documents
    Macro,
    
    /// JavaScript in PDFs
    JavaScript,
    
    /// Hidden executables
    Executable,
    
    /// Shell/PowerShell scripts
    Script,
    
    /// Unclassified threat
    Unknown,
}
```

### Detection Context

| ThreatType | Found In | Detection Method |
|------------|----------|------------------|
| Macro | Office docs | VBA markers, AutoOpen |
| JavaScript | PDFs | /JavaScript, /JS tags |
| Executable | Archives | MZ header (PE) |
| Script | Any | PowerShell, bash markers |

---

## FileCategory

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCategory {
    Image,
    Document,
    Archive,
    Executable,
    Multimedia,
    Text,
    Unknown,
}
```

### Usage

```rust
// Category affects threat assessment
let default_threat = match category {
    FileCategory::Executable => ThreatLevel::Suspicious,
    _ => ThreatLevel::Safe,
};

// Category determines which scans run
match category {
    FileCategory::Document => scan_for_macros(data),
    FileCategory::Archive => scan_for_executables(data),
    _ => vec![],
}
```

---

## DetectionError

```rust
#[derive(Error, Debug)]
pub enum DetectionError {
    /// I/O error during file reading
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// File exceeds size limit
    #[error("File too large: {0} bytes (max: {1})")]
    FileTooLarge(u64, u64),
    
    /// File structure is corrupted
    #[error("Corrupted file structure: {0}")]
    CorruptedStructure(String),
    
    /// Operation timed out
    #[error("Detection timeout after {0}ms")]
    Timeout(u64),
    
    /// File type not supported
    #[error("Unsupported file type")]
    Unsupported,
}
```

### Error Handling

```rust
use batin::{FileType, DetectionConfig, DetectionError};

match FileType::from_file_path("file.pdf", &config).await {
    Ok(result) => println!("Detected: {}", result.extension),
    Err(DetectionError::Io(e)) => eprintln!("I/O error: {}", e),
    Err(DetectionError::FileTooLarge(size, max)) => {
        eprintln!("File too large: {} > {}", size, max);
    }
    Err(DetectionError::Timeout(ms)) => {
        eprintln!("Timed out after {}ms", ms);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```
