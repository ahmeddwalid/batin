---
sidebar_position: 9
title: Configuration
description: Configuring Batin's detection behavior
---

# Configuration

Customize Batin's detection behavior for your use case.

## DetectionConfig

The `DetectionConfig` struct controls all detection parameters.

```rust
use batin::DetectionConfig;

let config = DetectionConfig {
    max_read_bytes: 3072,               // Bytes to read for detection
    enable_entropy: true,                // Enable entropy analysis
    enable_polyglot: true,               // Enable polyglot detection
    enable_embedded: true,               // Scan for embedded threats
    entropy_threshold: 7.2,              // Packed detection threshold
    packed_chi_square_threshold: 100.0,  // Chi-square threshold for packing
    encrypted_entropy_threshold: 7.8,    // Encryption detection threshold
    encrypted_chi_square_threshold: 50.0,// Chi-square for encryption
    timeout_ms: 5000,                    // File read timeout
};
```

## Configuration Options

### max_read_bytes

Maximum bytes to read from each file for signature detection.

| Value | Use Case |
|-------|----------|
| `1024` | Quick scans, reduce I/O |
| `3072` | **Default** - balanced |
| `8192` | Better accuracy for complex formats |
| `65536` | Deep analysis, slower |

```rust
let config = DetectionConfig {
    max_read_bytes: 8192, // Read more for better accuracy
    ..Default::default()
};
```

### enable_entropy

Toggle Shannon entropy analysis.

- **`true` (default)**: Calculate entropy, detect packed/encrypted
- **`false`**: Skip entropy analysis (faster)

```rust
// Fast scan without entropy
let config = DetectionConfig {
    enable_entropy: false,
    ..Default::default()
};
```

### enable_polyglot

Toggle multi-format detection.

- **`true` (default)**: Scan multiple offsets for hidden formats
- **`false`**: Only detect primary signature

```rust
// Skip polyglot detection
let config = DetectionConfig {
    enable_polyglot: false,
    ..Default::default()
};
```

### enable_embedded

Toggle embedded threat scanning.

- **`true` (default)**: Scan for macros, JavaScript, executables
- **`false`**: Skip embedded content analysis

```rust
// Skip embedded scanning
let config = DetectionConfig {
    enable_embedded: false,
    ..Default::default()
};
```

### Entropy Thresholds

Fine-tune packed/encrypted detection:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `entropy_threshold` | 7.2 | Min entropy for "packed" flag |
| `packed_chi_square_threshold` | 100.0 | Max chi-square for "packed" flag |
| `encrypted_entropy_threshold` | 7.8 | Min entropy for "encrypted" flag |
| `encrypted_chi_square_threshold` | 50.0 | Max chi-square for "encrypted" flag |

#### Understanding the Thresholds

**Packed files** have:

- High entropy (compressed data)
- Moderate chi-square (not perfectly random)

**Encrypted files** have:

- Very high entropy (near 8.0)
- Low chi-square (nearly uniform distribution)

```rust
// Stricter detection (fewer false positives)
let config = DetectionConfig {
    entropy_threshold: 7.5,          // Higher threshold
    encrypted_entropy_threshold: 7.9, // Near maximum
    ..Default::default()
};
```

### timeout_ms

Maximum time to spend reading a file.

- **`5000` (default)**: 5 seconds
- Prevents DoS from large/slow files

```rust
// Faster timeout for web applications
let config = DetectionConfig {
    timeout_ms: 2000, // 2 seconds
    ..Default::default()
};
```

---

## Preset Configurations

### Fast Scan (Minimal)

```rust
let fast_config = DetectionConfig {
    max_read_bytes: 1024,
    enable_entropy: false,
    enable_polyglot: false,
    enable_embedded: false,
    timeout_ms: 1000,
    ..Default::default()
};
```

### Security-Focused

```rust
let security_config = DetectionConfig {
    max_read_bytes: 8192,
    enable_entropy: true,
    enable_polyglot: true,
    enable_embedded: true,
    entropy_threshold: 7.0,  // Lower threshold (more sensitive)
    timeout_ms: 10000,
    ..Default::default()
};
```

### Forensic Analysis

```rust
let forensic_config = DetectionConfig {
    max_read_bytes: 65536,  // Read more data
    enable_entropy: true,
    enable_polyglot: true,
    enable_embedded: true,
    timeout_ms: 30000,      // Allow more time
    ..Default::default()
};
```

---

## Environment Variables

| Variable | CLI Equivalent | Description |
|----------|---------------|-------------|
| `BATIN_MAX_READ_BYTES` | N/A | Default max bytes |
| `BATIN_TIMEOUT_MS` | N/A | Default timeout |
| `NO_COLOR` | N/A | Disable colored output |
| `RUST_LOG` | `--verbose` | Log level |

```bash
# Example: Increase read bytes for all scans
export BATIN_MAX_READ_BYTES=8192
batin scan /directory -r
```

---

## Performance Tuning

### High-Throughput Scanning

```rust
// Minimize I/O and processing
let high_throughput = DetectionConfig {
    max_read_bytes: 512,    // Minimal read
    enable_entropy: false,   // Skip entropy
    enable_polyglot: false,  // Skip polyglot
    enable_embedded: false,  // Skip embedded
    timeout_ms: 500,         // Quick timeout
    ..Default::default()
};
```

### Memory-Constrained Environment

```rust
// Reduce memory usage
let low_memory = DetectionConfig {
    max_read_bytes: 1024,   // Small buffer
    enable_entropy: true,    // Entropy is O(1) memory
    enable_polyglot: false,  // Skip to reduce allocations
    enable_embedded: false,  // Skip to reduce allocations
    ..Default::default()
};
```

---

## Configuration for Specific File Types

### Document Analysis

```rust
let doc_config = DetectionConfig {
    enable_embedded: true,   // Detect macros
    enable_entropy: false,   // Usually not packed
    ..Default::default()
};
```

### Executable Analysis

```rust
let exe_config = DetectionConfig {
    enable_entropy: true,    // Detect packing
    enable_polyglot: true,   // Detect PDF+EXE attacks
    max_read_bytes: 8192,    // Read more for headers
    ..Default::default()
};
```

### Archive Analysis

```rust
let archive_config = DetectionConfig {
    enable_embedded: true,   // Find executables in archives
    max_read_bytes: 65536,   // Read central directory
    ..Default::default()
};
```
