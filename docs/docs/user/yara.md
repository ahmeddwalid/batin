---
title: YARA Rules
---

# YARA Rules

Batin can run your existing [YARA](https://virustotal.github.io/yara/) rules as
an additional detection stage, backed by the pure-Rust
[`yara-x`](https://github.com/VirusTotal/yara-x) engine. A rule match is
reported as a **Dangerous** embedded threat and escalates the file's threat
level.

This is an optional feature, kept out of the default build to keep dependencies
light.

## Building with YARA

```bash
cargo install batin --features yara
# or from source
cargo build --release --features "cli,yara"
```

Building the `yara` feature requires `protoc` (Protocol Buffers compiler) to be
installed.

## CLI usage

```bash
batin scan ./samples --yara rules/malware.yar
```

Every scanned file is matched against the compiled rules; matches appear in the
`embedded_threats` of the result.

## Library usage

```rust
use batin::{register_yara_rules_from_file, FileType, DetectionConfig};

register_yara_rules_from_file("rules/malware.yar")?;
let ft = FileType::from_bytes(data, &DetectionConfig::default())?;
for threat in &ft.embedded_threats {
    println!("{}", threat.description);
}
```

Custom detection stages are pluggable via the `Detector` trait; the YARA
integration is one implementation of it.
