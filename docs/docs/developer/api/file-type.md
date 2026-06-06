---
sidebar_position: 1
title: FileType API
description: Core FileType struct and methods
---

# FileType API Reference

The `FileType` struct is the main result type returned by detection operations.

## Struct Definition

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileType {
    /// Detected file extension (e.g., "pdf", "exe")
    pub extension: String,
    
    /// MIME type (e.g., "application/pdf")
    pub mime_type: String,
    
    /// Detection confidence (0.0 to 1.0)
    pub confidence: f64,
    
    /// Entropy analysis results
    pub entropy_profile: Option<EntropyProfile>,
    
    /// Assessed threat level
    pub threat_level: ThreatLevel,
    
    /// All formats detected (for polyglot files)
    pub detected_formats: Vec<String>,
    
    /// Embedded threats found
    pub embedded_threats: Vec<EmbeddedThreat>,
    
    /// File hashes (if computed)
    pub hashes: Option<FileHashes>,
    
    /// Binary metadata (PE/ELF/Mach-O)
    pub binary_metadata: Option<BinaryMetadata>,
}
```

---

## Methods

### `from_bytes`

Detect file type from a byte slice.

```rust
pub fn from_bytes(data: &[u8], config: &DetectionConfig) -> Result<Self>
```

**Parameters:**

- `data` - File content as bytes
- `config` - Detection configuration

**Returns:** `Result<FileType, DetectionError>`

**Example:**

```rust
use batin::{FileType, DetectionConfig};

let data = std::fs::read("sample.pdf")?;
let config = DetectionConfig::default();

let result = FileType::from_bytes(&data, &config)?;
println!("Type: {}", result.extension);
```

---

### `from_file_path`

Detect file type from a file path (async).

```rust
pub async fn from_file_path<P: AsRef<Path>>(
    path: P, 
    config: &DetectionConfig
) -> Result<Self>
```

**Parameters:**

- `path` - Path to the file
- `config` - Detection configuration

**Returns:** `Result<FileType, DetectionError>`

**Example:**

```rust
use batin::{FileType, DetectionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = DetectionConfig::default();
    let result = FileType::from_file_path("sample.pdf", &config).await?;
    
    println!("Type: {} ({})", result.extension, result.mime_type);
    println!("Threat: {:?}", result.threat_level);
    
    Ok(())
}
```

---

### `validate_extension`

Check if a claimed extension matches the detected type.

```rust
pub fn validate_extension(&self, claimed_ext: &str) -> bool
```

**Parameters:**

- `claimed_ext` - The extension claimed by the filename

**Returns:** `true` if extension matches detected type

**Example:**

```rust
let result = FileType::from_bytes(data, &config)?;

// User uploaded "document.pdf" but it's actually an EXE
if !result.validate_extension("pdf") {
    eprintln!("Extension mismatch! Claimed: pdf, Actual: {}", result.extension);
}
```

---

## Field Details

### `extension`

The most likely file extension based on detection.

- Always lowercase
- Without leading dot
- Examples: `"pdf"`, `"exe"`, `"png"`, `"unknown"`

### `mime_type`

Standard MIME type string.

- Examples: `"application/pdf"`, `"image/png"`
- `"application/octet-stream"` for unknown

### `confidence`

Detection confidence from 0.0 to 1.0.

| Range | Meaning |
|-------|---------|
| 0.9+ | Very confident (magic + validation) |
| 0.7-0.9 | Confident (magic match) |
| 0.5-0.7 | Moderate (partial match) |
| < 0.5 | Low (heuristics only) |

### `entropy_profile`

Optional entropy analysis results. `None` if `enable_entropy = false`.

```rust
if let Some(profile) = &result.entropy_profile {
    println!("Entropy: {:.2} bits/byte", profile.global_entropy);
    if profile.is_packed {
        println!("⚠️ File appears packed");
    }
}
```

### `threat_level`

Assessed risk level.

```rust
match result.threat_level {
    ThreatLevel::Safe => println!("✓ Safe"),
    ThreatLevel::Suspicious => println!("⚠ Suspicious"),
    ThreatLevel::Dangerous => println!("⚠ Dangerous"),
    ThreatLevel::Critical => println!("✖ Critical"),
}
```

### `detected_formats`

All formats detected (for polyglot detection).

```rust
if result.detected_formats.len() > 1 {
    println!("Polyglot detected: {:?}", result.detected_formats);
}
```

### `embedded_threats`

List of embedded threats found.

```rust
for threat in &result.embedded_threats {
    println!("{:?} at offset {} - {}", 
        threat.threat_type, 
        threat.offset,
        threat.description
    );
}
```

### `hashes`

Optional file hashes. `None` unless explicitly computed.

```rust
if let Some(hashes) = &result.hashes {
    println!("MD5: {}", hashes.md5);
    println!("SHA-256: {}", hashes.sha256);
}
```

### `binary_metadata`

Optional PE/ELF/Mach-O metadata.

```rust
if let Some(meta) = &result.binary_metadata {
    println!("Format: {:?}", meta.format);
    println!("Architecture: {}", meta.architecture);
    println!("64-bit: {}", meta.is_64bit);
}
```

---

## Serialization

`FileType` derives `serde::Serialize`:

```rust
let result = FileType::from_bytes(&data, &config)?;
let json = serde_json::to_string_pretty(&result)?;
println!("{}", json);
```

**Output:**

```json
{
  "extension": "pdf",
  "mime_type": "application/pdf",
  "confidence": 0.95,
  "entropy_profile": {
    "global_entropy": 4.23,
    "is_packed": false,
    "is_encrypted": false
  },
  "threat_level": "Safe",
  "detected_formats": ["pdf"],
  "embedded_threats": [],
  "hashes": null,
  "binary_metadata": null
}
```
