---
sidebar_position: 4
title: CLI Reference
description: Complete command-line interface documentation
---

# CLI Reference

Complete documentation for all Batin command-line options.

## Global Syntax

```bash
batin [GLOBAL OPTIONS] <COMMAND> [COMMAND OPTIONS]
```

## Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--json` | | Output results in JSON format |
| `--csv` | | Output results in CSV format |
| `--verbose` | `-v` | Enable verbose logging |
| `--help` | `-h` | Show help information |
| `--version` | `-V` | Show version information |

## Commands

### `scan` - Scan Files or Directories

Analyze files for type detection and threat assessment.

```bash
batin scan <PATH> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `PATH` | File or directory path to scan |

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--recursive` | `-r` | Scan directories recursively | `false` |
| `--output` | `-o` | Output file path for results | stdout |
| `--exclude` | `-e` | Exclude files matching glob pattern | none |
| `--min-threat` | | Minimum threat level to show | all |
| `--hash` | | Include MD5/SHA-256 hashes | `false` |

#### Threat Level Values

- `safe` - Show all files
- `suspicious` - Show suspicious and above
- `dangerous` - Show dangerous and critical only
- `critical` - Show only critical threats

#### Examples

```bash
# Basic file scan
batin scan document.pdf

# Recursive directory scan
batin scan /home/user/Downloads --recursive

# Exclude patterns
batin scan /project -r --exclude "*.log" --exclude "target/*"

# Show only dangerous files
batin scan /uploads -r --min-threat dangerous

# JSON output with hashes
batin scan /evidence -r --json --hash --output report.json

# CSV output
batin scan /samples -r --csv --output results.csv
```

---

### `watch` - Real-Time Monitoring

Monitor a directory for new and modified files in real-time.

```bash
batin watch <PATH> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `PATH` | Directory path to watch |

#### Behavior

- Monitors recursively by default
- Debounces duplicate events (200ms window)
- Waits for file stabilization before scanning (50ms)
- Shows live results as files are created/modified

#### Examples

```bash
# Watch downloads folder
batin watch ~/Downloads

# Watch with verbose logging
batin watch /var/log --verbose
```

#### Output Format

```
  HH:MM:SS ✓ filename.ext [type] threat_level
           └─ Additional details (if applicable)
```

---

## Output Formats

### Table (Default)

Human-readable table with colored output:

```
╭─────────────────┬──────┬────────────┬───────────┬───────────╮
│ File            │ Type │ Confidence │ Threat    │ Details   │
├─────────────────┼──────┼────────────┼───────────┼───────────┤
│ document.pdf    │ pdf  │ 95%        │ ✓ Safe    │ ─         │
│ malware.exe     │ exe  │ 90%        │ ⚠ Dangerous│ 📦 Packed │
╰─────────────────┴──────┴────────────┴───────────┴───────────╯
```

### JSON

```bash
batin scan file.pdf --json
```

```json
[
  {
    "path": "/path/to/file.pdf",
    "file_type": {
      "extension": "pdf",
      "mime_type": "application/pdf",
      "confidence": 0.95,
      "entropy_profile": {
        "global_entropy": 4.23,
        "chi_square": 245.8,
        "is_packed": false,
        "is_encrypted": false
      },
      "threat_level": "Safe",
      "detected_formats": ["pdf"],
      "embedded_threats": [],
      "hashes": null,
      "binary_metadata": null
    }
  }
]
```

### CSV

```bash
batin scan /dir -r --csv
```

```csv
Path,Type,MIME,Confidence,Threat Level,Entropy,Is Packed,Is Encrypted,Polyglot,Embedded Threats,MD5,SHA256
/path/file.pdf,pdf,application/pdf,95.0%,Safe,4.23,false,false,,,
/path/packed.exe,exe,application/x-dosexec,90.0%,Dangerous,7.85,true,false,,,
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success - all files processed |
| `1` | Error - file not found, permission denied, etc. |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BATIN_MAX_READ_BYTES` | Maximum bytes to read per file | 3072 |
| `BATIN_TIMEOUT_MS` | File read timeout in milliseconds | 5000 |
| `NO_COLOR` | Disable colored output | unset |

---

## Examples by Use Case

### Security Audit

```bash
# Scan uploads folder for threats, output JSON report
batin scan /var/www/uploads -r --json --hash \
  --min-threat suspicious \
  --output audit-report.json
```

### Malware Triage

```bash
# Quick scan of suspicious samples
batin scan /malware-samples -r --min-threat dangerous
```

### Forensic Investigation

```bash
# Full scan with hashes for evidence collection
batin scan /evidence -r --json --hash --output case-001.json
```

### CI/CD Pipeline

```bash
# Fail if any dangerous files found
batin scan ./dist -r --min-threat dangerous --json | jq -e 'length == 0'
```

### Watch Downloads (Interactive)

```bash
# Monitor and alert on new files
batin watch ~/Downloads -v
```

---

:::tip Pro Tip
Combine `--json` output with `jq` for powerful filtering:

```bash
batin scan /uploads -r --json | jq '.[] | select(.file_type.threat_level != "Safe")'
```

:::
