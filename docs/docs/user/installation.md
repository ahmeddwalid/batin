---
sidebar_position: 2
title: Installation
description: Install Batin on Linux, Windows, macOS, or FreeBSD
---

# Installation

Batin can be installed through various package managers or built from source. Choose the method that works best for your platform.

## Prerequisites

- **Rust 1.75+** (if building from source)
- **Node.js 18+** (if building documentation)

## Package Managers

### 🍎 macOS (Homebrew)

```bash
brew tap ahmeddwalid/batin
brew install batin
```

### 🐧 Arch Linux (AUR)

Using `yay`:

```bash
yay -S batin
```

Using `paru`:

```bash
paru -S batin
```

### 🎩 Fedora / RHEL (COPR)

```bash
sudo dnf copr enable ahmeddwalid/batin
sudo dnf install batin
```

### 🍥 Debian / Ubuntu

```bash
sudo add-apt-repository ppa:ahmeddwalid/batin
sudo apt update
sudo apt install batin
```

### 🪟 Windows (Chocolatey)

```powershell
choco install batin
```

### 😈 FreeBSD (Ports)

```bash
cd /usr/ports/security/batin
make install clean

# Or via pkg
pkg install batin
```

## Using Cargo

If you have Rust installed, you can install Batin directly from crates.io:

```bash
cargo install batin
```

### With Specific Features

```bash
# Full installation (all features)
cargo install batin --all-features

# Minimal installation (core detection only)
cargo install batin --no-default-features

# With specific features
cargo install batin --features "hashing,archive"
```

## Building from Source

### 1. Clone the Repository

```bash
git clone https://github.com/ahmeddwalid/batin.git
cd batin
```

### 2. Build Release Binary

```bash
cargo build --release
```

The binary will be at `target/release/batin`.

### 3. Install Locally

```bash
# Copy to a directory in your PATH
sudo cp target/release/batin /usr/local/bin/

# Or install via cargo
cargo install --path .
```

### 4. Verify Installation

```bash
batin --version
```

## Docker

### Pull from Docker Hub

```bash
docker pull ahmeddwalid/batin:latest
```

### Run Container

```bash
# Scan a single file
docker run --rm -v /path/to/files:/data ahmeddwalid/batin scan /data/file.pdf

# Scan a directory
docker run --rm -v /path/to/files:/data ahmeddwalid/batin scan /data --recursive
```

### Build Docker Image Locally

```bash
docker build -t batin .
```

## Verify Installation

After installation, verify Batin is working correctly:

```bash
# Check version
batin --version

# Run a test scan
echo "test" > /tmp/test.txt
batin scan /tmp/test.txt

# Expected output shows the file type detection result
```

## Platform Support

| Platform | x86_64 | x86_32 | ARM64 | ARMv7 | RISC-V |
|----------|:------:|:------:|:-----:|:-----:|:------:|
| **Linux** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Windows** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **macOS** | ✅ | ❌ | ✅ | ❌ | ❌ |
| **FreeBSD** | ✅ | ❓ | ❓ | ❌ | ❌ |

## Feature Flags

Batin supports optional features that can be enabled at compile time:

| Feature | Description | Default |
|---------|-------------|---------|
| `cli` | Command-line interface | ✅ |
| `hashing` | MD5/SHA-256 file hashing | ✅ |
| `binary-parsing` | PE/ELF metadata extraction | ✅ |
| `archive` | ZIP/TAR archive scanning | ✅ |

### Example: Minimal Build

```bash
cargo build --release --no-default-features
```

This builds only the core detection library without CLI or optional features.

---

:::tip Next Steps
Now that Batin is installed, head to the [Quick Start](./quickstart) guide to perform your first scan!
:::
