---
sidebar_position: 1
title: Contributing Guide
description: How to contribute to Batin
---

# Contributing to Batin

Thank you for your interest in contributing to Batin! This guide explains how to get started.

## Development Setup

### Prerequisites

- **Rust 1.75+** (rustup recommended)
- **Git** for version control
- **Cargo** for building and testing

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/ahmeddwalid/batin.git
cd batin

# Build in debug mode
cargo build

# Run tests
cargo test --all-features

# Run clippy lints
cargo clippy --all-features -- -D warnings

# Check formatting
cargo fmt --all -- --check
```

---

## Project Structure

```
batin/
├── src/                # Source code
│   ├── lib.rs         # Library entry point
│   ├── main.rs        # CLI binary
│   └── ...            # Modules
├── tests/             # Integration tests
├── examples/          # Usage examples
├── benches/           # Performance benchmarks
├── fuzz/              # Fuzz testing targets
└── docs/              # This documentation
```

---

## Contribution Workflow

### 1. Find an Issue

- Browse [open issues](https://github.com/ahmeddwalid/batin/issues)
- Look for `good first issue` labels
- Or open a new issue to discuss your idea

### 2. Fork and Branch

```bash
# Fork on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/batin.git
cd batin

# Create a feature branch
git checkout -b feature/your-feature-name
```

### 3. Make Changes

- Follow the code style (run `cargo fmt`)
- Add tests for new functionality
- Update documentation if needed
- Run the full test suite

### 4. Commit

```bash
git add .
git commit -m "feat: add support for XYZ format"
```

**Commit message format:**

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `test:` - Adding tests
- `refactor:` - Code refactoring
- `perf:` - Performance improvement

### 5. Push and Open PR

```bash
git push origin feature/your-feature-name
```

Then open a Pull Request on GitHub.

---

## Code Style

### Rust Style

- Follow standard Rust conventions
- Run `cargo fmt` before committing
- Fix all `clippy` warnings

### Documentation

Every public item should have:

- A doc comment (`///`)
- Example code where helpful
- Parameter descriptions

```rust
/// Detect file type from byte slice.
///
/// # Arguments
/// * `data` - The file content as bytes
/// * `config` - Detection configuration
///
/// # Returns
/// `Result<FileType>` with detection results
///
/// # Example
/// ```
/// let data = std::fs::read("file.pdf")?;
/// let result = FileType::from_bytes(&data, &config)?;
/// ```
pub fn from_bytes(data: &[u8], config: &DetectionConfig) -> Result<Self>
```

---

## Adding New File Signatures

### Step 1: Research

1. Find the format's specification
2. Identify magic bytes and offset
3. Check for similar formats that need disambiguation

### Step 2: Add Signature

In `src/detection/signatures.rs`:

```rust
FileSignature {
    magic: &[0x00, 0x00, 0x01, 0x00],
    offset: 0,
    additional_magic: None,
    extensions: vec!["ico".to_string()],
    mime_type: "image/x-icon",
    category: FileCategory::Image,
},
```

### Step 3: Add Test

```rust
#[test]
fn test_detect_ico() {
    let ico_data = include_bytes!("../test_files/sample.ico");
    let db = SignatureDatabase::default();
    let matches = db.match_signatures(ico_data);
    assert!(!matches.is_empty());
}
```

### Step 4: Update Documentation

Add the new format to `CHANGELOG.md` and README.

---

## Testing

### Unit Tests

```bash
# Run all tests
cargo test --all-features

# Run specific test
cargo test test_detect_ico

# Run with output
cargo test -- --nocapture
```

### Fuzz Testing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzz tests
cargo +nightly fuzz run fuzz_detect
```

### Benchmarks

```bash
# Run benchmarks
cargo bench
```

---

## Pull Request Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] `cargo clippy` passes
- [ ] `cargo fmt --check` passes
- [ ] New code has tests
- [ ] Documentation updated
- [ ] CHANGELOG updated (if applicable)

---

## Release Process

*For maintainers only*

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Commit: `git commit -m "release: v0.2.0"`
4. Tag: `git tag v0.2.0`
5. Push: `git push && git push --tags`
6. GitHub Actions handles the rest

---

## Getting Help

- **Questions?** Open a [Discussion](https://github.com/ahmeddwalid/batin/discussions)
- **Found a bug?** Open an [Issue](https://github.com/ahmeddwalid/batin/issues)
- **Security issue?** See [SECURITY.md](https://github.com/ahmeddwalid/batin/blob/main/SECURITY.md)

---

## License

By contributing, you agree that your contributions will be licensed under the GPL-3.0 license.

---

:::tip First Time Contributing?
Look for issues labeled `good first issue` - they're specifically chosen to be approachable for new contributors!
:::
