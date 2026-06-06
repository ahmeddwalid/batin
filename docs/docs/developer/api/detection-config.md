---
sidebar_position: 2
title: DetectionConfig API
description: Configuration options for detection behavior
---

# DetectionConfig API Reference

Configure Batin's detection behavior.

## Struct Definition

```rust
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// Maximum bytes to read from file (default: 3072)
    pub max_read_bytes: usize,
    
    /// Enable entropy analysis (default: true)
    pub enable_entropy: bool,
    
    /// Enable polyglot detection (default: true)
    pub enable_polyglot: bool,
    
    /// Enable embedded threat scanning (default: true)
    pub enable_embedded: bool,
    
    /// Entropy threshold for "packed" detection (default: 7.2)
    pub entropy_threshold: f64,
    
    /// Chi-square threshold for packed files (default: 100.0)
    pub packed_chi_square_threshold: f64,
    
    /// Entropy threshold for "encrypted" detection (default: 7.8)
    pub encrypted_entropy_threshold: f64,
    
    /// Chi-square threshold for encrypted files (default: 50.0)
    pub encrypted_chi_square_threshold: f64,
    
    /// Timeout for file operations in milliseconds (default: 5000)
    pub timeout_ms: u64,
}
```

---

## Default Implementation

```rust
impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            max_read_bytes: 3072,
            enable_entropy: true,
            enable_polyglot: true,
            enable_embedded: true,
            entropy_threshold: 7.2,
            packed_chi_square_threshold: 100.0,
            encrypted_entropy_threshold: 7.8,
            encrypted_chi_square_threshold: 50.0,
            timeout_ms: 5000,
        }
    }
}
```

---

## Usage

### Default Configuration

```rust
use batin::DetectionConfig;

let config = DetectionConfig::default();
```

### Custom Configuration

```rust
let config = DetectionConfig {
    max_read_bytes: 8192,
    enable_entropy: true,
    enable_polyglot: true,
    enable_embedded: true,
    entropy_threshold: 7.5,
    ..Default::default()
};
```

---

## Field Reference

### `max_read_bytes`

Maximum bytes to read from each file.

| Value | Use Case |
|-------|----------|
| `1024` | Quick scans, minimal I/O |
| `3072` | **Default** - balanced |
| `8192` | Better accuracy |
| `65536` | Deep analysis |

### `enable_entropy`

Toggle Shannon entropy analysis.

- `true`: Calculate entropy, detect packed/encrypted
- `false`: Skip entropy (faster)

### `enable_polyglot`

Toggle polyglot (multi-format) detection.

- `true`: Check multiple offsets for hidden formats
- `false`: Only detect primary format

### `enable_embedded`

Toggle embedded threat scanning.

- `true`: Scan for macros, JavaScript, executables
- `false`: Skip embedded content analysis

### `entropy_threshold`

Minimum entropy (bits/byte) to flag as "packed".

- Default: `7.2`
- Higher = fewer false positives
- Lower = more sensitive

### `packed_chi_square_threshold`

Maximum chi-square to flag as "packed".

- Default: `100.0`
- Packed files have low chi-square (not perfectly random)

### `encrypted_entropy_threshold`

Minimum entropy to flag as "encrypted".

- Default: `7.8`
- Encrypted data has near-maximum entropy

### `encrypted_chi_square_threshold`

Maximum chi-square to flag as "encrypted".

- Default: `50.0`
- Encrypted data has nearly uniform distribution

### `timeout_ms`

Maximum time for file operations.

- Default: `5000` (5 seconds)
- Prevents DoS from slow/hanging files

---

## Presets

### Fast Scan

```rust
let fast = DetectionConfig {
    max_read_bytes: 1024,
    enable_entropy: false,
    enable_polyglot: false,
    enable_embedded: false,
    timeout_ms: 1000,
    ..Default::default()
};
```

### Security Focused

```rust
let security = DetectionConfig {
    max_read_bytes: 8192,
    enable_entropy: true,
    enable_polyglot: true,
    enable_embedded: true,
    entropy_threshold: 7.0,  // More sensitive
    timeout_ms: 10000,
    ..Default::default()
};
```

### Forensic Analysis

```rust
let forensic = DetectionConfig {
    max_read_bytes: 65536,
    enable_entropy: true,
    enable_polyglot: true,
    enable_embedded: true,
    timeout_ms: 30000,
    ..Default::default()
};
```
