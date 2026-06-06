---
title: Threat Model & Limitations
---

# Threat Model & Limitations

Batin is a **triage and identification** tool. It is designed to quickly flag
suspicious files in a pipeline, not to replace a sandbox or a full anti-virus
engine. Understanding its boundaries is essential for using it safely.

## What Batin does well

- **Fast format identification** from magic bytes, structure, and content.
- **Entropy profiling** to flag packed/encrypted regions.
- **Polyglot detection** (files valid as multiple formats).
- **Extension-spoofing detection** (declared vs. actual type).
- **Lightweight embedded-threat heuristics**: Office macros, PDF auto-actions,
  base64/XOR-encoded executables, executables inside archives.
- **Structural validation** (e.g. PNG chunk CRCs) to detect tampering.
- **Bounded, panic-free parsing**, fuzz-tested, with zero `unsafe` in the core.

## What Batin does not do

- **It does not execute or sandbox files.** There is no behavioural analysis.
- **It is not a signature-complete AV.** Embedded-threat detection is
  heuristic and can be evaded by determined attackers (e.g. multi-byte XOR,
  custom packers, novel obfuscation).
- **It does not unpack or decrypt payloads.** High entropy is reported, not
  resolved.
- **Text/format classification is heuristic** for files without magic bytes and
  carries lower confidence.

## Security properties

- The core library is `#![forbid(unsafe_code)]`. The only `unsafe` lives in the
  optional C-ABI crate, which is a thin, documented FFI shim.
- All parsing is bounded: reads are capped (`max_read_bytes`), archive
  extraction enforces size/entry/depth limits, and operations have timeouts.
- Detection never panics on malformed input. This is enforced by continuous
  fuzzing in CI (`fuzz_detect`, `fuzz_archive`, `fuzz_entropy`, `fuzz_binary`).

## Recommended use

Use Batin as a **first-pass filter**: triage uploads, route suspicious files to
deeper analysis (a sandbox, YARA rule sets, or an AV), and enrich with hash
reputation. Treat a `Safe` result as "no cheap red flags found", not as a
guarantee of safety.
