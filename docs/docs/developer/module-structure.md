---
sidebar_position: 3
title: Module Structure
description: Understanding Batin's codebase organization
---

# Module Structure

Guide to Batin's source code organization and module responsibilities.

## Directory Layout

```
src/
├── lib.rs              # Library entry point, core types
├── main.rs             # CLI binary entry point
├── utils.rs            # Shared utility functions
│
├── detection/          # File type detection
│   ├── mod.rs          # Module exports
│   ├── signatures.rs   # Magic byte database
│   ├── entropy.rs      # Entropy calculations
│   ├── polyglot.rs     # Multi-format detection
│   └── embedded.rs     # Embedded threat scanning
│
├── analysis/           # Deep file analysis
│   ├── mod.rs          # Module exports
│   ├── validation.rs   # Structure validation
│   ├── forensics.rs    # Fragment classification
│   └── binary.rs       # PE/ELF/Mach-O parsing
│
├── io/                 # I/O operations
│   ├── mod.rs          # Module exports
│   ├── batch.rs        # Parallel file processing
│   ├── archive.rs      # Archive extraction
│   └── hasher.rs       # File hashing
│
└── cli/                # Command-line interface
    ├── mod.rs          # CLI module exports
    ├── scanner.rs      # Scan command
    ├── watcher.rs      # Watch command
    └── console.rs      # Terminal theming
```

---

## Core Module: `lib.rs`

### Responsibilities

1. **Define core types** (`FileType`, `DetectionConfig`, `ThreatLevel`)
2. **Main detection API** (`from_bytes`, `from_file_path`)
3. **Re-export** public items from submodules
4. **Error types** (`DetectionError`)

### Key Code Sections

```rust
// Error types
#[derive(Error, Debug)]
pub enum DetectionError {
    Io(#[from] std::io::Error),
    FileTooLarge(u64, u64),
    CorruptedStructure(String),
    Timeout(u64),
    Unsupported,
}

// Configuration
pub struct DetectionConfig {
    pub max_read_bytes: usize,
    pub enable_entropy: bool,
    pub enable_polyglot: bool,
    pub enable_embedded: bool,
    pub entropy_threshold: f64,
    pub timeout_ms: u64,
}

// Main result type
pub struct FileType {
    pub extension: String,
    pub mime_type: String,
    pub confidence: f64,
    pub entropy_profile: Option<EntropyProfile>,
    pub threat_level: ThreatLevel,
    pub detected_formats: Vec<String>,
    pub embedded_threats: Vec<EmbeddedThreat>,
    pub hashes: Option<FileHashes>,
    pub binary_metadata: Option<BinaryMetadata>,
}
```

### Why Centralized?

- **Single import**: Users only need `use batin::*`
- **Consistent types**: All modules use same definitions
- **Version stability**: Public API in one place

---

## Detection Module

### `signatures.rs`

**Purpose:** Magic byte signature database

**Key Components:**

```rust
// Thread-safe global database
pub static SIGNATURE_DB: LazyLock<RwLock<SignatureDatabase>>

// Signature definition
pub struct FileSignature {
    pub magic: &'static [u8],          // Magic bytes
    pub offset: usize,                  // Offset in file
    pub additional_magic: Option<...>,  // Secondary validation
    pub extensions: Vec<String>,        // File extensions
    pub mime_type: &'static str,        // MIME type
    pub category: FileCategory,         // Classification
}

// Database with 60+ formats
pub struct SignatureDatabase {
    pub signatures: Vec<FileSignature>,
    pub extension_map: HashMap<String, Vec<usize>>,
}
```

**Key Methods:**

| Method | Purpose |
|--------|---------|
| `match_signatures(data)` | Find matching signatures |
| `detect_iso_base_media_format(data)` | Disambiguate MP4/MOV/HEIC |
| `detect_zip_format(data)` | Disambiguate DOCX/JAR/EPUB |

### `entropy.rs`

**Purpose:** Shannon entropy and chi-square calculations

**Key Functions:**

```rust
// Single-pass statistics
pub fn calculate_entropy_stats(data: &[u8]) -> EntropyStats

// Individual calculations (use calculate_entropy_stats for efficiency)
pub fn calculate_shannon_entropy(data: &[u8]) -> f64
pub fn chi_square_test(data: &[u8]) -> f64

// Comprehensive analysis
pub fn analyze_entropy(
    data: &[u8], 
    packed_threshold: f64
) -> Result<EntropyProfile>

// Windowed analysis for finding hidden data
pub fn sliding_window_entropy(
    data: &[u8], 
    window_size: usize
) -> Vec<f64>
```

### `polyglot.rs`

**Purpose:** Detect files valid in multiple formats

**Key Function:**

```rust
pub fn detect_polyglot(
    data: &[u8], 
    db: &SignatureDatabase
) -> Result<Vec<String>>
```

**Algorithm:**

1. Check offsets 0, 512, 1024, 2048
2. Match signatures at each offset
3. Special-case PDF+EXE detection
4. Return all unique formats found

### `embedded.rs`

**Purpose:** Scan for embedded malicious content

**Key Types:**

```rust
pub struct EmbeddedThreat {
    pub threat_type: ThreatType,
    pub offset: usize,
    pub severity: ThreatLevel,
    pub description: String,
}

pub enum ThreatType {
    Macro,
    JavaScript,
    Executable,
    Script,
    Unknown,
}
```

**Key Functions:**

| Function | Scans For |
|----------|-----------|
| `scan_embedded_content(data, sig)` | All threats based on category |
| `detect_macros(data)` | VBA, AutoOpen, AutoExec |
| `detect_pdf_javascript(data)` | /JavaScript, /JS |
| `detect_executable_in_archive(data)` | MZ header in archive |

---

## Analysis Module

### `validation.rs`

**Purpose:** Validate file structure beyond magic bytes

**Functions:**

```rust
pub fn validate_pdf(data: &[u8]) -> ValidationResult
pub fn validate_png(data: &[u8]) -> ValidationResult
pub fn validate_zip(data: &[u8]) -> ValidationResult
pub fn validate_pe(data: &[u8]) -> ValidationResult
pub fn is_dotnet_assembly(data: &[u8]) -> bool
```

**Example: PDF Validation**

```rust
pub fn validate_pdf(data: &[u8]) -> ValidationResult {
    // Check header
    if &data[0..5] != b"%PDF-" {
        return ValidationResult { is_valid: false, ... };
    }
    
    // Check EOF marker
    let has_eof = find_pattern_reverse(data, b"%%EOF").is_some();
    
    // Check xref table
    let has_xref = find_pattern(data, b"xref").is_some();
    
    ValidationResult {
        is_valid: has_eof && has_xref,
        confidence_boost: 0.1,
        details: "Valid PDF structure".to_string(),
    }
}
```

### `forensics.rs`

**Purpose:** Classify file fragments without headers

```rust
pub fn classify_fragment(data: &[u8]) -> Result<FragmentClassification>

pub struct FragmentClassification {
    pub likely_type: String,
    pub confidence: f64,
    pub entropy: f64,
}
```

### `binary.rs`

**Purpose:** Extract metadata from executables

```rust
pub fn parse_binary(data: &[u8]) -> Option<BinaryMetadata>

pub struct BinaryMetadata {
    pub format: BinaryFormat,  // PE, ELF, MachO
    pub architecture: String,
    pub is_64bit: bool,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
}
```

---

## I/O Module

### `batch.rs`

**Purpose:** Parallel file processing

```rust
pub struct BatchProcessor {
    config: DetectionConfig,
}

impl BatchProcessor {
    pub async fn process_directory(
        &self,
        path: &str,
        progress: Option<mpsc::UnboundedSender<BatchProgress>>,
    ) -> Result<Vec<(PathBuf, Result<FileType>)>>
}

pub struct BatchProgress {
    pub total: usize,
    pub processed: usize,
    pub current_file: PathBuf,
}
```

### `archive.rs`

**Purpose:** Safe archive extraction and scanning

```rust
// Safety limits
const MAX_EXTRACTED_FILE_SIZE: u64 = 50_000_000;      // 50MB per file
const MAX_TOTAL_EXTRACTED_SIZE: u64 = 100_000_000;    // 100MB total
const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const SUSPICIOUS_COMPRESSION_RATIO: u64 = 100;

pub async fn scan_archive(
    data: &[u8],
    config: &DetectionConfig,
) -> Result<Vec<ArchiveEntry>>
```

### `hasher.rs`

**Purpose:** File hash calculation

```rust
pub fn compute_hashes(data: &[u8]) -> FileHashes

pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
}
```

---

## CLI Module

### `scanner.rs`

**Purpose:** Implement `batin scan` command

```rust
pub struct ScanOptions {
    pub recursive: bool,
    pub json: bool,
    pub csv: bool,
    pub verbose: bool,
    pub output: Option<PathBuf>,
    pub exclude: Vec<String>,
    pub min_threat: Option<ThreatLevel>,
    pub include_hash: bool,
}

pub async fn run_scan(path: PathBuf, options: ScanOptions) -> Result<()>
```

### `watcher.rs`

**Purpose:** Implement `batin watch` command

```rust
pub async fn run_watch(path: PathBuf, verbose: bool) -> Result<()>
```

Uses `notify` crate for filesystem events with debouncing.

### `console.rs`

**Purpose:** Terminal theming and output formatting

```rust
pub mod theme {
    pub const SUCCESS: Color = Color::Green;
    pub const WARNING: Color = Color::Yellow;
    pub const DANGER: Color = Color::Red;
    pub const MUTED: Color = Color::BrightBlack;
}

pub fn print_banner()
pub fn print_separator()
pub fn threat_icon(level: &ThreatLevel) -> &'static str
pub fn threat_color(level: &ThreatLevel) -> Color
```

---

## Utilities: `utils.rs`

Shared functions used across modules:

```rust
// Find first occurrence of pattern
pub fn find_bytes(data: &[u8], pattern: &[u8]) -> Option<usize>

// Find all occurrences
pub fn find_all_bytes(data: &[u8], pattern: &[u8]) -> Vec<usize>

// Read little-endian u32
pub fn read_le_u32(data: &[u8], offset: usize) -> Option<u32>

// Read big-endian u32
pub fn read_be_u32(data: &[u8], offset: usize) -> Option<u32>
```

---

## Feature Flags

```toml
[features]
default = ["full"]
full = ["hashing", "binary-parsing", "archive", "cli"]

hashing = ["md-5", "sha2"]        # io/hasher.rs
binary-parsing = ["goblin"]       # analysis/binary.rs
archive = ["zip", "tar", "flate2"]# io/archive.rs
cli = ["clap", "colored", ...]    # cli/*
```

**Why optional features?**

- Smaller binary for library-only use
- Fewer dependencies when not needed
- Faster compilation for core features

---

:::tip Contributor Tip
When adding new functionality:

1. **Detection logic** → `detection/` module
2. **Deep analysis** → `analysis/` module
3. **File I/O** → `io/` module
4. **CLI commands** → `cli/` module
5. **Shared utilities** → `utils.rs`
:::
