
# Batin

### Security-Hardened File Type Detection in Rust

<p align="center">
  <strong>Professional-grade file identification using magic bytes, Shannon entropy, and advanced threat detection for cybersecurity applications</strong>
</p>

<p align="center">
  <a href="#features">Features</a>
  .
  <a href="#installation">Installation</a> 
  .
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
    <a href="https://github.com/ahmeddwalid/batin/issues">Report Bug</a>
    ·
    <a href="https://github.com/ahmeddwalid/batin/pulls">Request Feature</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.75%2B-orange?style=for-the-badge&logo=rust" alt="Rust 1.75+"/>
  <img src="https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/unsafe-forbidden-success?style=for-the-badge" alt="Unsafe Forbidden"/>
  <img src="https://img.shields.io/badge/Fuzz%20Tested-✓-brightgreen?style=for-the-badge" alt="Fuzz Tested"/>
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black" alt="Linux"/>
  <img src="https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white" alt="Windows"/>
  <img src="https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white" alt="macOS"/>
  <img src="https://img.shields.io/badge/FreeBSD-AB2B28?style=flat&logo=freebsd&logoColor=white" alt="FreeBSD"/>
</p>

<p align="center">
  <a href="https://ahmeddwalid.github.io/batin/"><strong>Explore the docs »</strong></a>
</p>

</div>

---

## Table of Contents

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
   </li>
   <li><a href="#features">Features</a></li>
    <li><a href="#Installation">Installation</a></li>
    <li><a href="#security-features">Contributing</a></li>
    <li><a href="Contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#Acknowledgments">Acknowledgments</a></li>
    <li><a href="#contact">Contact</a></li>
    <li>
    <a href="#acknowledgments">Acknowledgments</a>
    </li>
  </ol>
</details>

---

## About The Project

**Batin** is a zero-`unsafe`, production-ready Rust library designed for cybersecurity professionals, malware analysis teams, digital forensics investigators, and security researchers. Unlike traditional file type detection tools that only examine magic bytes, Batin employs a multi stage detection pipeline combining signature analysis, Shannon entropy calculations, polyglot detection, and embedded threat scanning to identify malicious files that evade conventional security controls.

Batin detects:

- **Polyglot files** valid in multiple formats simultaneously (PDF+EXE attacks)
- **Packed/encrypted executables** using entropy profiling
- **Extension spoofing** attempts for data exfiltration
- **Embedded threats** like macros in documents and scripts in PDFs
- **File fragments** without headers for memory forensics

---

## Features

| Capability                   | Description                                                                                                                                               |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **50+ File Formats**         | Detects Office (DOCX, ODF, RTF), Media (Images, Audio, Video), Dev (Class, Pyc, Wasm), Containers (Docker, ISO), Archives (TAR, XZ, ZST), and Executables |
| **Shannon Entropy Analysis** | Calculates file randomness (0.0-8.0 bits/byte) to detect packed code, encryption, and compression                                                         |
| **Sliding Window Entropy**   | Generates entropy graphs to find small encrypted payloads hidden in larger files                                                                          |
| **Polyglot Detection**       | Identifies files interpretable as multiple formats—common malware evasion technique                                                                       |
| **Extension Validation**     | Compares declared extensions against true content to prevent spoofing attacks                                                                             |
| **Embedded Threat Scanning** | Detects Office macros, PDF JavaScript, and executables hidden in archives                                                                                 |
| **Fragment Classification**  | Identifies partial files without headers using statistical analysis                                                                                       |
| **Zero Unsafe Code**         | Built entirely with safe Rust using `RwLock` and `LazyLock`                                                                                               |
| **Async & Parallel**         | Tokio for I/O, Rayon for CPU-bound entropy calculations                                                                                                   |
| **Fuzz Tested**              | Cargo-fuzz integration guarantees no panics on malformed input                                                                                            |

<p align="right">(<a href="#top">back to top</a>)</p>

---

## Installation

### Cross Platform Support

Batin supports the following platforms and architectures:

| Platform    | x86_64 | x86_32 | ARM64 | ARMv7 | RISC-V |
| ----------- |:------:|:------:|:-----:|:-----:|:------:|
| **Linux**   | ✅     | ✅     | ✅    | ✅    | ✅     |
| **Windows** | ✅     | ✅     | ✅    | ❌    | ❌     |
| **macOS**   | ✅     | ❌     | ✅    | ❌    | ❌     |
| **FreeBSD** | ✅     | ❌     | ❌    | ❌    | ❌     |

### Building from Source

```bash
# Clone the repository
git clone https://github.com/ahmeddwalid/batin.git
cd batin

# Build the library
cargo build --release

# Run tests
cargo test
```

---

## Command-Line Tool

Batin includes a powerful CLI tool for analyzing files directly from the terminal.

### Installation

```bash
# Install from source
cargo install --path .

# Or build and run directly
cargo build --release
./target/release/batin --help
```

### Usage

```bash
# Scan a single file
batin scan -p suspicious.exe

# Recursive directory scan
batin scan -p ./Downloads --recursive

# Output in JSON format
batin scan -p ./malware_samples --recursive --json --output results.json

# Enable verbose logging
batin scan -p document.docx -v
```

### CLI Options

| Command | Option         | Short | Description                                                         |
| ------- | -------------- | ----- | ------------------------------------------------------------------- |
| `scan`  | `path`         |       | Input path to analyze (file or directory)                           |
| `scan`  | `--recursive`  | `-r`  | Enable recursive directory scanning                                 |
| `scan`  | `--output`     | `-o`  | Output file path for results                                        |
| `scan`  | `--exclude`    | `-e`  | Exclude files matching glob pattern (repeatable)                    |
| `scan`  | `--min-threat` |       | Minimum threat level to show: safe, suspicious, dangerous, critical |
| `scan`  | `--hash`       |       | Include MD5/SHA-256 file hashes in output                           |
| `watch` | `path`         |       | Watch a directory for new files in real-time                        |
| Global  | `--json`       |       | Output results in JSON format                                       |
| Global  | `--csv`        |       | Output results in CSV format                                        |
| Global  | `--verbose`    | `-v`  | Enable verbose logging                                              |

<p align="right">(<a href="#top">back to top</a>)</p>

---

## Security Features

### Polyglot Detection

Polyglot files are valid in multiple formats simultaneously. It's a common malware technique to bypass security scanners. Batin detects these by:

1. Scanning multiple offsets (0, 512, 1024, 2048 bytes)
2. Checking for signatures at each location
3. Identifying suspicious combinations (e.g., PDF + PE)
4. Returning all detected formats with confidence scores

**Example Attack Scenario:**

```
A PDF document that's also a valid Windows executable. Email scanners see 
a PDF and allow it through. When executed, Windows runs the embedded EXE.
```

### Entropy-Based Malware Detection

High entropy indicates randomness, which suggests:

- **Packing/Compression**: Malware authors pack executables to evade signature detection
- **Encryption**: Ransomware encrypts payloads before execution
- **Steganography**: Hidden data embedded in images/audio

**Entropy Thresholds:**

- `< 4.0`: Text files, uncompressed data
- `4.0 - 6.5`: Compiled code, binary data
- `6.5 - 7.5`: Compressed archives (legitimate)
- `> 7.5`: Encrypted/packed (suspicious)

### Extension Spoofing Detection

Attackers rename malicious executables to appear benign:

```
malware.exe → invoice.pdf.exe (Windows hides .exe)
ransomware.exe → document.docx (Linux/macOS)
```

Batin validates that file extensions match true content, flagging mismatches for investigation.

### Embedded Threat Scanning

Malware often hides inside legitimate files:

- **Office Macros**: VBA scripts in `.docx`, `.xlsx` that download malware
- **PDF JavaScript**: Scripts that exploit PDF reader vulnerabilities  
- **Archive Executables**: `.zip` files containing hidden `.exe` payloads

Batin recursively scans containers and documents for these threats.

<p align="right">(<a href="#top">back to top</a>)</p>

---

## Contributing

Contributions are **greatly appreciated**! Whether you're fixing bugs, adding features, or improving documentation, we welcome your help.

### How to Contribute

1. **Fork the repository**: Create your own copy
2. **Create a branch**: `git checkout -b feature/amazing-feature`
3. **Implement your changes**: Follow Rust best practices
4. **Write tests**: Ensure new code is tested
5. **Run checks**: `cargo test && cargo clippy && cargo fmt`
6. **Commit**: `git commit -m "Add amazing feature"`
7. **Push**: `git push origin feature/amazing-feature`
8. **Open Pull Request**: Submit your changes for review

### Contribution Guidelines

- **No `unsafe` code**: All contributions must use safe Rust
- **Add tests**: New features require unit tests
- **Document**: Public APIs need doc comments with examples
- **Format**: Run `cargo fmt` before committing
- **Lint**: Address all `cargo clippy` warnings
- **Fuzz test**: Verify robustness with `cargo fuzz`

### Development Setup

```
# Clone repository
git clone https://github.com/ahmeddwalid/batin.git
cd batin

# Install development tools
rustup component add clippy rustfmt
cargo install cargo-fuzz cargo-tarpaulin

# Run full test suite
cargo test --all-features
cargo clippy --all-targets --all-features
cargo fmt --check

# Run fuzzer (Ctrl+C to stop)
cargo fuzz run fuzz_detect
```

### Code of Conduct

- Be respectful and considerate
- Provide constructive feedback
- Focus on technical merit
- Welcome newcomers

Thank you for contributing to Batin!

<p align="right">(<a href="#top">back to top</a>)</p>

---

## License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

<p align="right">(<a href="#top">back to top</a>)</p>

---

## Acknowledgments

### Research & Inspiration

- [Google Magika](https://arxiv.org/pdf/2409.13768.pdf) - Deep learning file type detection
- [PolyConv Model](https://d197for5662m48.cloudfront.net/documents/publicationstatus/226865/preprint_pdf/2e54078748e2d64f334225ff91e8f300.pdf) - Polyglot detection with 99.20% F1 score
- [FiFTy Neural Network](https://www.sciencedirect.com/science/article/abs/pii/S0167404821002017) - File fragment classification
- [OPSWAT Research](https://www.gopher.security/news/unmasking-polyglot-files-threat-detection-and-mitigation-strategies) - Multi-stage detection pipelines

### Libraries & Tools

- [infer](https://github.com/bojand/infer) - Rust file type inference library
- [tree_magic](https://docs.rs/tree_magic/) - MIME type detection
- [shannon-entropy](https://github.com/jme/shannon-rust) - Entropy calculation reference
- [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) - Fuzzing framework

### Documentation & Standards

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) - Naming conventions
- [NIST SP 800-86](https://csrc.nist.gov/publications/detail/sp/800-86/final) - Digital forensics guide
- [OWASP File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) - Security best practices

### Community

- [/r/rust](https://www.reddit.com/r/rust/) - Community support
- [Rust Users Forum](https://users.rust-lang.org/) - Technical discussions

<p align="right">(<a href="#top">back to top</a>)</p>

---

## Contact

**Ahmed Walid**

- Email: [devahmedwalid@proton.me](mailto:devahmedwalid@proton.me)
- GitHub: [@ahmeddwalid](https://github.com/ahmeddwalid)
- LinkedIn: [Ahmed Walid](https://linkedin.com/in/ahmeddwalid)

**Project Link**: [https://github.com/ahmeddwalid/batin](https://github.com/ahmeddwalid/batin)

For security vulnerabilities, please email directly instead of opening public issues.

<p align="right">(<a href="#top">back to top</a>)</p>

---
