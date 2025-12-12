# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-12

### Added

- **Multi-stage file type detection** using magic bytes, entropy analysis, and content validation
- **60+ file format signatures** including images, documents, archives, executables, and multimedia
- **Shannon entropy analysis** with single-pass calculation and sliding window support
- **Polyglot file detection** for files valid in multiple formats
- **Embedded threat scanning** for macros, scripts, and hidden executables
- **Extension validation** and spoofing detection
- **File fragment classification** for forensic analysis
- **Real-time directory monitoring** with `batin watch <path>`
- **ZIP format detection** distinguishing DOCX/XLSX/ODF/JAR/EPUB
- **Batch processing** with async I/O and parallel entropy calculation
- **Command-line interface** with JSON/CSV output support
- **Comprehensive test suite** with unit and integration tests
- **GitHub Actions CI/CD** for Linux, macOS, Windows, and FreeBSD builds

### Supported File Formats

- **Images**: PNG, JPEG, GIF, BMP, WebP, TIFF, HEIC, AVIF, ICO, PSD, JXL, SVG
- **Documents**: PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT, RTF, ODT, ODS, ODP, EPUB
- **Archives**: ZIP, RAR, 7Z, GZIP, BZ2, XZ, ZST, LZ4, TAR, CAB, DEB, RPM, ISO
- **Executables**: PE (EXE/DLL), ELF, Mach-O, Java class, WebAssembly, DEX, Python bytecode
- **Multimedia**: MP3, MP4, M4A, M4V, AVI, WAV, FLAC, OGG, MKV, WebM, MOV, WMA, AAC, Opus
- **Data**: SQLite, QCOW2, VMDK

### Security Features

- Zero unsafe code (`#![forbid(unsafe_code)]`)
- Packed executable detection using entropy thresholds
- Chi-square testing for encryption detection
- Multi-offset polyglot scanning
- Office macro detection (VBA, AutoOpen, AutoExec)
- PDF JavaScript detection
- Archive executable scanning
- Threat level assessment (Safe, Suspicious, Dangerous, Critical)
- Zip bomb protection with size limits

### Performance

- Single-pass entropy and chi-square calculation
- Async I/O with Tokio
- Parallel processing with Rayon
- Lazy signature database initialization
- Configurable timeout protection
- Memory-efficient bounded reads

[0.1.0]: https://github.com/ahmeddwalid/batin/releases/tag/v0.1.0
