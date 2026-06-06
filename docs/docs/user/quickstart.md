---
sidebar_position: 3
title: Quick Start
description: Get started with Batin in 5 minutes
---

# Quick Start

This guide will get you scanning files in under 5 minutes.

## Your First Scan

### Scanning a Single File

```bash
batin scan suspicious.exe
```

**Example Output:**

```
╭──────────────────────────────────────────────────────────────╮
│                         🔍 BATIN                              │
│          Security-Hardened File Type Detection               │
╰──────────────────────────────────────────────────────────────╯

╭─────────────────┬──────┬────────────┬───────────┬───────────╮
│ File            │ Type │ Confidence │ Threat    │ Details   │
├─────────────────┼──────┼────────────┼───────────┼───────────┤
│ suspicious.exe  │ exe  │ 95%        │ ⚠ Suspicious │ 📦 Packed │
╰─────────────────┴──────┴────────────┴───────────┴───────────╯

── Scan Summary ───────────────────────────────────────────────

Safe       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0 (0%)
Suspicious ████████████████████████████████ 1 (100%)

📊 Scanned 1 file in 12ms
```

### Understanding the Output

| Column | Description |
|--------|-------------|
| **File** | Path to the scanned file |
| **Type** | Detected file type (based on content, not extension) |
| **Confidence** | How confident Batin is in the detection (0-100%) |
| **Threat** | Risk assessment level |
| **Details** | Additional flags (Packed, Encrypted, Polyglot, etc.) |

### Threat Levels

| Level | Icon | Meaning |
|-------|------|---------|
| **Safe** | ✓ | No threats detected |
| **Suspicious** | ⚠ | Potentially risky (e.g., executables, scripts) |
| **Dangerous** | ⚠ | High risk (packed, polyglot, or embedded threats) |
| **Critical** | ✖ | Immediate threat (auto-execute macros detected) |

## Scanning Directories

### Recursive Scan

```bash
batin scan /path/to/directory --recursive
```

### With Progress Bar

When scanning large directories, Batin shows a progress bar:

```
🔍 Scanning: /home/user/Downloads

  [00:00:05] ▕████████████░░░░░░░░░░░░░░░░░░▏ 125/350 (35%) • ETA: 9s
  Scanning: document.pdf
```

## Filtering Results

### Show Only Threats

```bash
batin scan /downloads --recursive --min-threat suspicious
```

### Exclude Patterns

```bash
batin scan /project --recursive --exclude "*.log" --exclude "node_modules/*"
```

## Output Formats

### JSON Output

```bash
batin scan file.pdf --json
```

```json
[
  {
    "path": "file.pdf",
    "file_type": {
      "extension": "pdf",
      "mime_type": "application/pdf",
      "confidence": 0.95,
      "threat_level": "Safe",
      "detected_formats": ["pdf"],
      "embedded_threats": []
    }
  }
]
```

### CSV Output

```bash
batin scan /directory --recursive --csv --output results.csv
```

### Save Results to File

```bash
batin scan /downloads --recursive --json --output scan-report.json
```

## Real-Time Monitoring

Watch a directory for new files:

```bash
batin watch /downloads
```

**Output:**

```
👁 Watching: /downloads
⏳ Monitoring for new and modified files...
Press Ctrl+C to stop watching.

  14:32:15 ✓ invoice.pdf [pdf] safe
  14:32:18 ⚠ download.exe [exe] suspicious
           └─ 📦 Packed executable detected
           └─ 📊 Entropy: 7.85 bits/byte
  14:32:21 ✓ photo.jpg [jpg] safe
```

## Including File Hashes

Generate MD5 and SHA-256 hashes:

```bash
batin scan important.doc --hash
```

```json
{
  "path": "important.doc",
  "file_type": {
    "extension": "doc",
    "hashes": {
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb924..."
    }
  }
}
```

## Using as a Library

### Add to Cargo.toml

```toml
[dependencies]
batin = "0.1"
tokio = { version = "1", features = ["full"] }
```

### Basic Usage

```rust
use batin::{FileType, DetectionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use default configuration
    let config = DetectionConfig::default();
    
    // Detect from file path (async)
    let result = FileType::from_file_path("test.pdf", &config).await?;
    
    println!("Type: {}", result.extension);
    println!("MIME: {}", result.mime_type);
    println!("Threat: {:?}", result.threat_level);
    
    // Check for polyglot
    if result.detected_formats.len() > 1 {
        println!("⚠️ Polyglot detected: {:?}", result.detected_formats);
    }
    
    // Check entropy
    if let Some(entropy) = result.entropy_profile {
        println!("Entropy: {:.2} bits/byte", entropy.global_entropy);
        if entropy.is_packed {
            println!("⚠️ File appears to be packed!");
        }
    }
    
    Ok(())
}
```

### Detect from Bytes

```rust
use batin::{FileType, DetectionConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read("sample.bin")?;
    let config = DetectionConfig::default();
    
    // Synchronous detection from bytes
    let result = FileType::from_bytes(&data, &config)?;
    
    println!("Detected: {}", result.extension);
    
    Ok(())
}
```

---

:::tip Next Steps

- Learn about all CLI options in the [CLI Reference](./cli-reference)
- Explore [Use Cases](./use-cases) for practical examples
- Understand [Threat Levels](./threat-levels) in depth
:::
