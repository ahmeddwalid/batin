---
sidebar_position: 5
title: Output Formats
description: Understanding Batin's output formats
---

# Output Formats

Batin supports multiple output formats for different use cases.

## Table Format (Default)

The default human-readable format with color-coded threat levels.

```bash
batin scan /samples -r
```

### Components

1. **Banner** - ASCII art header with version info
2. **Progress Bar** - Shown during directory scans
3. **Results Table** - File-by-file detection results
4. **Summary** - Statistics and recommendations

### Customization

| Disable Colors | Command |
|----------------|---------|
| Environment variable | `NO_COLOR=1 batin scan file.pdf` |
| Pipe output | `batin scan file.pdf | cat` |

---

## JSON Format

Machine-readable format for automation and integration.

```bash
batin scan /samples -r --json
```

### Schema

```json
{
  "path": "string",
  "file_type": {
    "extension": "string",
    "mime_type": "string",
    "confidence": "number (0.0-1.0)",
    "entropy_profile": {
      "global_entropy": "number (0.0-8.0)",
      "block_entropies": ["array of numbers"],
      "chi_square": "number",
      "is_packed": "boolean",
      "is_encrypted": "boolean"
    },
    "threat_level": "Safe | Suspicious | Dangerous | Critical",
    "detected_formats": ["array of strings"],
    "embedded_threats": [
      {
        "threat_type": "Macro | JavaScript | Executable | Script | Unknown",
        "offset": "number",
        "severity": "Safe | Suspicious | Dangerous | Critical",
        "description": "string"
      }
    ],
    "hashes": {
      "md5": "string (32 hex chars)",
      "sha256": "string (64 hex chars)"
    },
    "binary_metadata": {
      "format": "PE | ELF | MachO",
      "architecture": "string",
      "is_64bit": "boolean",
      "imports": ["array of strings"],
      "exports": ["array of strings"]
    }
  }
}
```

### Processing with jq

```bash
# Extract only dangerous files
batin scan /uploads -r --json | jq '.[] | select(.file_type.threat_level == "Dangerous")'

# Get file paths with high entropy
batin scan /samples -r --json | jq '.[] | select(.file_type.entropy_profile.global_entropy > 7.5) | .path'

# Count by threat level
batin scan /dir -r --json | jq 'group_by(.file_type.threat_level) | map({level: .[0].file_type.threat_level, count: length})'
```

---

## CSV Format

Spreadsheet-compatible format for reporting and analysis.

```bash
batin scan /samples -r --csv --output report.csv
```

### Columns

| Column | Description |
|--------|-------------|
| Path | Full file path |
| Type | Detected extension |
| MIME | MIME type |
| Confidence | Detection confidence percentage |
| Threat Level | Risk assessment |
| Entropy | Global entropy value |
| Is Packed | Whether file appears packed |
| Is Encrypted | Whether file appears encrypted |
| Polyglot | Additional formats (if polyglot) |
| Embedded Threats | Detected threats |
| MD5 | MD5 hash (if `--hash` used) |
| SHA256 | SHA-256 hash (if `--hash` used) |

### Import to Excel/Sheets

1. Save output: `batin scan /dir -r --csv --output results.csv`
2. Open in Excel/Google Sheets
3. Data is automatically parsed into columns

---

## Saving Output

### To File

```bash
# JSON to file
batin scan /samples -r --json --output report.json

# CSV to file
batin scan /samples -r --csv --output report.csv

# Table to file (redirect)
batin scan /samples -r > report.txt
```

### Append to File

```bash
batin scan /new-samples -r --json >> all-results.json
```

---

## Integration Examples

### Python Script

```python
import subprocess
import json

result = subprocess.run(
    ["batin", "scan", "/uploads", "-r", "--json"],
    capture_output=True,
    text=True
)

data = json.loads(result.stdout)
threats = [f for f in data if f["file_type"]["threat_level"] != "Safe"]

for threat in threats:
    print(f"⚠️ {threat['path']}: {threat['file_type']['threat_level']}")
```

### Bash Script

```bash
#!/bin/bash

# Scan and alert on threats
RESULT=$(batin scan /uploads -r --json)
THREATS=$(echo "$RESULT" | jq '[.[] | select(.file_type.threat_level != "Safe")] | length')

if [ "$THREATS" -gt 0 ]; then
    echo "⚠️ Found $THREATS suspicious files!"
    exit 1
fi

echo "✅ All clear!"
```

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    batin scan ./dist -r --json --output scan-results.json
    
- name: Check for Threats
  run: |
    THREATS=$(jq '[.[] | select(.file_type.threat_level != "Safe")] | length' scan-results.json)
    if [ "$THREATS" -gt 0 ]; then
      echo "::error::Found $THREATS suspicious files"
      exit 1
    fi
```
