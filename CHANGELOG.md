# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-06

First public release.

### Detection

- Multi-stage detection pipeline: magic-byte signatures, Shannon entropy,
  polyglot detection, threat assessment, and embedded-content scanning.
- 60+ built-in format signatures across images, documents, archives,
  executables, multimedia, fonts, and Windows shortcuts.
- Shannon entropy analysis with single-pass calculation, chi-square testing,
  and sliding-window profiling for packed/encrypted regions.
- Polyglot detection for files valid as multiple formats.
- Extension-spoofing detection, surfaced as non-fatal warnings on the result.
- File-fragment classification for headerless data.
- Real PE, ELF, and Mach-O parsing (including fat/universal Mach-O binaries).
- Configuration validation with clear errors for out-of-range values.

### Extensibility

- User-loadable JSON signatures merged at runtime, via the library or the
  `batin scan --signatures <file>` flag.
- A `Detector` trait and registry so custom detection stages can be plugged in
  without forking.
- Optional YARA rule scanning (`yara` feature) backed by the pure-Rust
  `yara-x` engine, exposed as a detector and the `--yara` flag.

### Threat analysis

- Office macro detection reporting every auto-execute marker found.
- PDF analysis covering JavaScript and auto-action/launch triggers
  (`/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`).
- Detection of base64-encoded and single-byte XOR-encoded executables.
- Structural validation beyond magic bytes, including PNG chunk CRC-32
  verification to catch tampering.
- Recursive scanning of ZIP, TAR, and tar.gz archives with configurable
  size, entry-count, depth, and compression-ratio limits, plus zip-bomb
  protection.

### Output and integration

- Output formats: table, JSON, NDJSON, CSV, SARIF 2.1.0, and a self-contained
  HTML report.
- Parallel directory scanning with a configurable concurrency level.
- Local hash-reputation denylist (`--hash-deny`) and optional VirusTotal
  lookups (`online` feature, `batin reputation`).
- HTTP API daemon (`server` feature, `batin serve`) with graceful shutdown.
- C ABI bindings (`batin-capi`) and WebAssembly bindings (`batin-wasm`); the
  synchronous detection core builds for `wasm32` with no async dependencies.
- Shell completions and a generated man page.
- Real-time directory monitoring with `batin watch`, with graceful
  SIGINT/SIGTERM shutdown.

### Supported file formats

- Images: PNG, JPEG, GIF, BMP, WebP, TIFF, HEIC, AVIF, ICO, PSD, JXL, SVG
- Documents: PDF, DOCX, XLSX, PPTX, DOC, XLS, PPT, RTF, ODT, ODS, ODP, EPUB
- Fonts: TTF, OTF, WOFF, WOFF2
- Archives: ZIP, RAR, 7Z, GZIP, BZ2, XZ, ZST, LZ4, TAR, CAB, DEB, RPM, ISO
- Executables: PE (EXE/DLL), ELF, Mach-O, Java class, WebAssembly, DEX,
  Python bytecode, Windows shortcuts (.lnk)
- Multimedia: MP3, MP4, M4A, M4V, AVI, WAV, FLAC, OGG, MKV, WebM, MOV, WMA,
  AAC, Opus
- Data: SQLite, QCOW2, VMDK, Windows registry hives

### Security and reliability

- Core library is `#![forbid(unsafe_code)]`; the only unsafe lives in the
  documented C ABI shim.
- Bounded, panic-free parsing enforced by continuous fuzzing
  (`fuzz_detect`, `fuzz_archive`, `fuzz_entropy`, `fuzz_binary`).
- Threat-level assessment (Safe, Suspicious, Dangerous, Critical) that
  escalates on embedded and custom-detector findings.
- Timeout protection and memory-efficient bounded reads.

### Build and tooling

- Feature-gated optional dependencies: `async`, `hashing`, `binary-parsing`,
  `archive`, `cli`, `yara`, `server`, `online`.
- Cargo-based packaging for Homebrew, AUR, RPM, Debian, Chocolatey, and
  FreeBSD, plus a multi-stage Docker image and `cargo-binstall` support.
- CI across Linux, macOS, and Windows with clippy, rustfmt, MSRV checks,
  coverage, benchmarks, `cargo-audit`, and `cargo-deny`.

[0.1.0]: https://github.com/ahmeddwalid/batin/releases/tag/v0.1.0
