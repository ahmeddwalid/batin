# Contributing to Batin

Thank you for your interest in contributing to Batin! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Style Guide](#style-guide)

## Code of Conduct

This project adheres to the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:

   ```bash
   git clone https://github.com/YOUR_USERNAME/batin.git
   cd batin
   ```

3. Add the upstream repository:

   ```bash
   git remote add upstream https://github.com/ahmeddwalid/batin.git
   ```

## Development Setup

### Prerequisites

- Rust 1.75 or later
- Cargo
- Git

### Install Development Dependencies

```bash
# Install Rust components
rustup component add clippy rustfmt

# Install development tools
cargo install cargo-watch
cargo install cargo-tarpaulin  # For coverage
```

### Build the Project

```bash
cargo build
cargo test
```

## Making Changes

### Before You Start

1. Create a new branch from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Keep your branch focused on a single feature or bugfix

### Coding Guidelines

- **No `unsafe` code**: All contributions must use safe Rust
- **Follow Rust conventions**: Use `rustfmt` and fix all `clippy` warnings
- **Add tests**: New features require unit tests
- **Document**: Public APIs need doc comments with examples
- **Keep it simple**: Prefer clarity over cleverness

## Testing

### Run Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with logging
RUST_LOG=debug cargo test
```

### Add Tests

- Unit tests: Add `#[test]` functions in the same file
- Integration tests: Create files in `tests/` directory
- Examples: Add runnable examples in `examples/` directory

### Test Requirements

All contributions MUST pass the following before submitting:

```bash
# All tests must pass
cargo test --all-features

# No clippy warnings
cargo clippy --all-features -- -D warnings

# Code must be formatted
cargo fmt --check

# Feature-gated code must compile
cargo check --no-default-features
cargo check --features hashing
cargo check --features binary-parsing
cargo check --features archive
```

### Test Coverage

```bash
cargo tarpaulin --out Html
```

## Submitting Changes

### Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass:

   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt --check
   ```

4. Update CHANGELOG.md
5. Commit your changes:

   ```bash
   git commit -m "feat: add amazing feature"
   ```

6. Push to your fork:

   ```bash
   git push origin feature/your-feature-name
   ```

7. Open a Pull Request on GitHub

### Commit Message Format

Follow conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated and passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No clippy warnings
- [ ] Code formatted with rustfmt

## Style Guide

### Rust Style

```rust
// Good: Clear, documented function
/// Calculate file entropy
///
/// # Arguments
/// * `data` - File bytes to analyze
///
/// # Returns
/// Entropy value between 0.0 and 8.0
pub fn calculate_entropy(data: &[u8]) -> f64 {
    // Implementation
}

// Bad: No documentation, unclear naming
pub fn calc(d: &[u8]) -> f64 {
    // Implementation
}
```

### Documentation

- Use `///` for public items
- Include examples in doc comments
- Explain *why*, not just *what*
- Keep lines under 100 characters

### Error Handling

- Use `Result<T>` for fallible operations
- Provide context with custom error types
- Never use `unwrap()` in library code
- Use `?` operator for error propagation

## Questions?

Feel free to open an issue for:

- Bug reports
- Feature requests
- Questions about the code
- Clarification on guidelines

Thank you for contributing to Batin!
