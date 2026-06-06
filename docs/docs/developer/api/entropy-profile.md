---
sidebar_position: 3
title: EntropyProfile API
description: Entropy analysis result types
---

# EntropyProfile API Reference

Results from entropy analysis.

## Struct Definition

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct EntropyProfile {
    /// Global Shannon entropy (0.0 to 8.0 bits/byte)
    pub global_entropy: f64,
    
    /// Block-wise entropy values for visualization
    pub block_entropies: Vec<f64>,
    
    /// Chi-square statistic
    pub chi_square: f64,
    
    /// True if file appears packed
    pub is_packed: bool,
    
    /// True if file appears encrypted
    pub is_encrypted: bool,
}
```

---

## Field Reference

### `global_entropy`

Overall Shannon entropy of the file.

| Range | Interpretation |
|-------|----------------|
| 0.0 - 4.0 | Plain text |
| 4.0 - 6.5 | Binary data |
| 6.5 - 7.5 | Compressed |
| 7.5 - 8.0 | Packed/Encrypted |

### `block_entropies`

Entropy calculated for each block (for visualization).

```rust
if let Some(profile) = &result.entropy_profile {
    for (i, entropy) in profile.block_entropies.iter().enumerate() {
        println!("Block {}: {:.2} bits/byte", i, entropy);
    }
}
```

### `chi_square`

Chi-square statistic measuring uniformity of byte distribution.

| Range | Interpretation |
|-------|----------------|
| < 50 | Very uniform (encrypted) |
| 50 - 150 | Somewhat uniform (packed/compressed) |
| 150 - 500 | Normal variation |
| > 500 | Non-uniform (text) |

### `is_packed`

True if the file appears to be a packed executable.

Criteria:

- `global_entropy > entropy_threshold` (default 7.2)
- `chi_square < packed_chi_square_threshold` (default 100)

### `is_encrypted`

True if the file appears to be encrypted.

Criteria:

- `global_entropy > encrypted_entropy_threshold` (default 7.8)
- `chi_square < encrypted_chi_square_threshold` (default 50)

---

## Usage

```rust
use batin::{FileType, DetectionConfig};

let config = DetectionConfig::default();
let result = FileType::from_bytes(&data, &config)?;

if let Some(profile) = &result.entropy_profile {
    println!("Entropy: {:.2} bits/byte", profile.global_entropy);
    println!("Chi-square: {:.1}", profile.chi_square);
    
    if profile.is_packed {
        println!("⚠️ File appears to be packed");
    }
    
    if profile.is_encrypted {
        println!("🔒 File appears to be encrypted");
    }
}
```

---

## Related Functions

### `calculate_entropy_stats`

Single-pass entropy and chi-square calculation.

```rust
pub fn calculate_entropy_stats(data: &[u8]) -> EntropyStats
```

### `analyze_entropy`

Full entropy analysis with packed/encrypted detection.

```rust
pub fn analyze_entropy(
    data: &[u8], 
    packed_threshold: f64
) -> Result<EntropyProfile>
```

### `sliding_window_entropy`

Calculate entropy across sliding windows.

```rust
pub fn sliding_window_entropy(
    data: &[u8], 
    window_size: usize
) -> Vec<f64>
```
