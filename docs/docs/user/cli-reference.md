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

These options apply to any command.

| Option | Short | Description |
|--------|-------|-------------|
| `--format <FORMAT>` | | Output format: `table`, `json`, `csv`, `ndjson`, `sarif`, or `html` |
| `--json` | | Shorthand for `--format json` |
| `--csv` | | Shorthand for `--format csv` |
| `--yara <FILE>` | | Load and apply YARA rules from a file (needs the `yara` build feature) |
| `--verbose` | `-v` | Enable verbose logging |
| `--help` | `-h` | Show help information |
| `--version` | `-V` | Show version information |

If both `--format` and `--json`/`--csv` are given, `--format` wins.

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
| `--exclude` | `-e` | Exclude files matching glob pattern (repeatable) | none |
| `--min-threat` | | Minimum threat level to show | all |
| `--hash` | | Include MD5/SHA-256 hashes | `false` |
| `--scan-archives` | | Recurse into ZIP/TAR/tar.gz and report nested entries | `false` |
| `--max-archive-depth` | | Maximum archive recursion depth | `4` |
| `--signatures <FILE>` | | Load extra JSON signatures before scanning | none |
| `--concurrency <N>` | | Files to detect in parallel (`0` = auto) | `0` |
| `--hash-deny <FILE>` | | Flag files whose SHA-256 is in this denylist | none |

Nested archive entries are reported with a `path` of `archive::inner/file`.

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

The watcher stops cleanly on Ctrl+C (SIGINT) or SIGTERM.

---

### `completions` - Shell Completions

Print a completion script for your shell to stdout.

```bash
batin completions <SHELL>
```

`SHELL` is one of `bash`, `zsh`, `fish`, `elvish`, or `powershell`.

```bash
# Install bash completions for the current user
batin completions bash > ~/.local/share/bash-completion/completions/batin
```

---

### `man` - Man Page

Print a roff man page to stdout.

```bash
batin man > batin.1
```

---

### `serve` - HTTP API Daemon

Run a small HTTP service for detection. Requires the `server` build feature.

```bash
batin serve [--addr <ADDR>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--addr` | Address to bind | `127.0.0.1:8080` |

Endpoints:

- `GET /health` returns `200 ok`
- `POST /scan` detects the request body and returns the result as JSON

```bash
curl --data-binary @suspicious.exe http://127.0.0.1:8080/scan
```

The server stops cleanly on Ctrl+C or SIGTERM.

---

### `reputation` - Hash Reputation Lookup

Look up a SHA-256 on VirusTotal. Requires the `online` build feature.

```bash
batin reputation <SHA256> [--api-key <KEY>]
```

The API key may be passed with `--api-key` or the `VT_API_KEY` environment
variable. The command exits `2` if the hash is flagged by any engine.

```bash
export VT_API_KEY=your_key_here
batin reputation 44d88612fea8a8f36de82e1278abb02f
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
      "binary_metadata": null,
      "warnings": []
    }
  }
]
```

The `warnings` array carries non-fatal notices such as an extension mismatch.

### Other formats

`--format ndjson` emits one JSON object per line (useful for streaming into
log pipelines). `--format sarif` produces a SARIF 2.1.0 report for code-scanning
dashboards. `--format html` writes a self-contained report. See
[Output Formats](output-formats) for full examples of each.

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
| `0` | Success |
| `1` | Error, such as a missing file, bad argument, or a missing build feature |
| `2` | `reputation`: the hash was flagged by at least one engine |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VT_API_KEY` | VirusTotal API key for `batin reputation` (`online` feature) |
| `RUST_LOG` | Log filter for tracing output (for example `RUST_LOG=debug`) |
| `NO_COLOR` | Disable colored output when set |

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
