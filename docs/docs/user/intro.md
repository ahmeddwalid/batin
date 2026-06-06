---
sidebar_position: 1
title: Introduction
description: Learn about Batin - a security-hardened file type detection library
---

# Introduction to Batin

**Batin** (باطن - Arabic for "hidden" or "inner") is a professional-grade, security-hardened file type detection library written in Rust. Unlike simple tools that only check file extensions, Batin examines the actual content of files to reveal their true nature.

## Why Batin?

Traditional file type detection tools have significant limitations:

| Tool | Limitation |
|------|------------|
| File extensions | Easily renamed/spoofed |
| Basic magic bytes | Only checks first few bytes |
| `file` command | No threat assessment, limited polyglot detection |

**Batin goes further** by combining multiple detection techniques:

```mermaid
flowchart LR
    A[File Input] --> B[Magic Bytes]
    B --> C[Entropy Analysis]
    C --> D[Polyglot Detection]
    D --> E[Threat Scanning]
    E --> F[Detection Result]
    
    style A fill:#1a1a2e
    style F fill:#25c2a0
```

## Key Features

### 🔍 Multi-Stage Detection

Batin doesn't just look at magic bytes. It analyzes:

- **Magic byte signatures** - Pattern matching against 60+ formats
- **Shannon entropy** - Detects packed/encrypted content
- **Multi-offset scanning** - Finds hidden formats (polyglots)
- **Embedded threat scanning** - Finds macros, scripts, executables

### 🛡️ Security-First Design

- **Zero `unsafe` code** - Guaranteed memory safety
- **No panics** - Fuzz tested to handle any input
- **Bounded reads** - Prevents memory exhaustion attacks
- **Timeout protection** - Prevents DoS from malformed files

### ⚡ High Performance

- **Async I/O** - Non-blocking file operations
- **Parallel processing** - Multi-core entropy calculation
- **Single-pass algorithms** - Optimized calculations

### 🌍 Cross-Platform

Works on Linux, Windows, macOS, and FreeBSD.

## Use Cases

### Malware Analysis

Detect packed executables, polyglot files (PDF+EXE attacks), and embedded macros before they execute.

### Digital Forensics

Identify file fragments, validate file integrity, and detect extension spoofing during investigations.

### Security Auditing

Scan directories for suspicious files, identify policy violations, and generate compliance reports.

### Content Filtering

Validate uploaded files in web applications, email gateways, and file sharing services.

## Quick Example

```rust
use batin::{FileType, DetectionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = DetectionConfig::default();
    let result = FileType::from_file_path("suspicious.pdf", &config).await?;
    
    println!("Detected: {} ({})", result.extension, result.mime_type);
    println!("Threat Level: {:?}", result.threat_level);
    
    if let Some(entropy) = result.entropy_profile {
        if entropy.is_packed {
            println!("⚠️ Warning: File appears to be packed!");
        }
    }
    
    Ok(())
}
```

## What's Next?

- [Installation Guide](./installation) - Get Batin installed on your system
- [Quick Start](./quickstart) - Your first scan in 5 minutes
- [CLI Reference](./cli-reference) - Complete command-line documentation

---

:::tip Ready to get started?
Jump to the [Installation Guide](./installation) to install Batin on your system.
:::
