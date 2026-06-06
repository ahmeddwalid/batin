---
sidebar_position: 6
title: Use Cases
description: Real-world applications of Batin
---

# Use Cases

Practical examples of how Batin is used in security operations.

## Malware Analysis Workflow

### Triage Incoming Samples

```bash
# Quick assessment of sample batch
batin scan /malware-inbox -r --min-threat suspicious --json | \
  jq '.[] | {path, type: .file_type.extension, threat: .file_type.threat_level}'
```

### Identify Packed Executables

Packed executables have high entropy (>7.0 bits/byte) and are often malware:

```bash
batin scan /samples -r --json | \
  jq '.[] | select(.file_type.entropy_profile.is_packed == true)'
```

### Detect Polyglot Attacks

Polyglot files (valid in multiple formats) are a common evasion technique:

```bash
batin scan /suspicious -r --json | \
  jq '.[] | select(.file_type.detected_formats | length > 1)'
```

### Extract Indicators

```bash
# Get hashes for threat intelligence
batin scan /confirmed-malware -r --json --hash | \
  jq '.[] | {hash: .file_type.hashes.sha256, type: .file_type.extension}'
```

---

## Digital Forensics

### Evidence Collection

```bash
# Full scan with hashes for chain of custody
batin scan /evidence/disk-image -r --json --hash \
  --output case-2024-001-scan.json
```

### Identify File Fragments

When analyzing disk images, many files may be incomplete:

```rust
use batin::forensics::classify_fragment;

fn analyze_sector(data: &[u8]) {
    let classification = classify_fragment(data).unwrap();
    
    println!("Likely type: {}", classification.likely_type);
    println!("Confidence: {:.1}%", classification.confidence * 100.0);
    println!("Entropy: {:.2}", classification.entropy);
}
```

### Detect Hidden Executables

Files with wrong extensions may indicate data hiding:

```bash
batin scan /evidence -r --json | \
  jq '.[] | select(.path | endswith(".jpg")) | select(.file_type.extension != "jpg")'
```

### Timeline Analysis

Log all file detections for timeline reconstruction:

```bash
batin watch /monitored-folder 2>&1 | \
  while read line; do
    echo "[$(date -Iseconds)] $line" >> detection-log.txt
  done
```

---

## Security Auditing

### Web Application Upload Validation

Scan uploaded files before processing:

```rust
use batin::{FileType, DetectionConfig, ThreatLevel};

async fn validate_upload(data: &[u8]) -> Result<(), String> {
    let config = DetectionConfig::default();
    let result = FileType::from_bytes(data, &config)
        .map_err(|e| format!("Detection failed: {}", e))?;
    
    // Block dangerous files
    if matches!(result.threat_level, ThreatLevel::Dangerous | ThreatLevel::Critical) {
        return Err(format!("File rejected: {:?}", result.threat_level));
    }
    
    // Block executables
    if matches!(result.extension.as_str(), "exe" | "dll" | "bat" | "cmd" | "ps1") {
        return Err("Executable files not allowed".to_string());
    }
    
    // Verify extension matches content
    let claimed_ext = "pdf"; // from user input
    if !result.validate_extension(claimed_ext) {
        return Err("File extension mismatch".to_string());
    }
    
    Ok(())
}
```

### Compliance Scanning

Regularly scan directories for policy violations:

```bash
#!/bin/bash
# compliance-scan.sh

SCAN_DIR="/shared-drive"
VIOLATIONS=$(batin scan "$SCAN_DIR" -r --json --min-threat suspicious | jq length)

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "Policy violation: $VIOLATIONS suspicious files found"
    batin scan "$SCAN_DIR" -r --min-threat suspicious
    exit 1
fi

echo "Compliance check passed"
```

### Email Gateway Filtering

```python
import subprocess
import json
import tempfile

def scan_attachment(data: bytes, filename: str) -> dict:
    """Scan email attachment before delivery."""
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=filename) as f:
        f.write(data)
        temp_path = f.name
    
    result = subprocess.run(
        ["batin", "scan", temp_path, "--json"],
        capture_output=True,
        text=True
    )
    
    scan_result = json.loads(result.stdout)[0]
    threat = scan_result["file_type"]["threat_level"]
    
    if threat in ["Dangerous", "Critical"]:
        return {"action": "quarantine", "reason": threat}
    
    if threat == "Suspicious":
        return {"action": "warn", "reason": "Potentially risky attachment"}
    
    return {"action": "allow"}
```

---

## CI/CD Integration

### Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Scan staged binary files
SUSPICIOUS=$(git diff --cached --name-only --diff-filter=A | \
  xargs -I {} batin scan {} --json 2>/dev/null | \
  jq '[.[] | select(.file_type.threat_level != "Safe")] | length')

if [ "$SUSPICIOUS" -gt 0 ]; then
    echo "❌ Commit blocked: suspicious files detected"
    exit 1
fi
```

### GitHub Actions Workflow

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Batin
        run: cargo install batin
      
      - name: Scan Repository
        run: |
          batin scan . -r --json --output scan-results.json
          
      - name: Check Results
        run: |
          THREATS=$(jq '[.[] | select(.file_type.threat_level != "Safe")] | length' scan-results.json)
          if [ "$THREATS" -gt 0 ]; then
            echo "::error::Found $THREATS suspicious files"
            jq '.[] | select(.file_type.threat_level != "Safe")' scan-results.json
            exit 1
          fi
          
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: security-scan
          path: scan-results.json
```

---

## Real-Time Protection

### Download Monitoring

```bash
# Monitor Downloads folder
batin watch ~/Downloads --verbose
```

### Automated Response

```bash
#!/bin/bash
# quarantine-watcher.sh

WATCH_DIR="/uploads"
QUARANTINE_DIR="/quarantine"

batin watch "$WATCH_DIR" --json 2>&1 | while read -r line; do
    THREAT=$(echo "$line" | jq -r '.file_type.threat_level // empty')
    FILE=$(echo "$line" | jq -r '.path // empty')
    
    if [[ "$THREAT" == "Dangerous" || "$THREAT" == "Critical" ]]; then
        mv "$FILE" "$QUARANTINE_DIR/"
        echo "$(date): Quarantined $FILE ($THREAT)" >> /var/log/batin-quarantine.log
    fi
done
```

---

:::tip Best Practices

1. **Always use `--hash`** for forensic work to maintain evidence integrity
2. **Use `--json`** for automation and integration with other tools
3. **Set appropriate `--min-threat`** to reduce noise in busy environments
4. **Combine with `jq`** for powerful filtering and analysis
5. **Use `watch` mode** for real-time protection of sensitive directories

:::
