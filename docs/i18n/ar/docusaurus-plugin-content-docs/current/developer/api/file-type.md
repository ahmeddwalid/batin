---
sidebar_position: 1
title: FileType API
description: مرجع API لـ FileType struct
---

# مرجع FileType API

التوثيق الكامل لنوع `FileType` الأساسي.

## التعريف

```rust
pub struct FileType {
    pub extension: String,
    pub mime_type: String,
    pub confidence: f64,
    pub entropy_profile: Option<EntropyProfile>,
    pub threat_level: ThreatLevel,
    pub detected_formats: Vec<String>,
    pub embedded_threats: Vec<EmbeddedThreat>,
    pub hashes: Option<FileHashes>,
    pub binary_metadata: Option<BinaryMetadata>,
}
```

## الحقول

| الحقل | النوع | الوصف |
|-------|-------|-------|
| `extension` | `String` | امتداد الملف المكتشف |
| `mime_type` | `String` | نوع MIME |
| `confidence` | `f64` | درجة الثقة (0.0-1.0) |
| `threat_level` | `ThreatLevel` | تقييم الخطورة |
| `detected_formats` | `Vec<String>` | كل الصيغ المكتشفة |

## الدوال الثابتة

### from_bytes

```rust
pub async fn from_bytes(
    data: &[u8], 
    config: &DetectionConfig
) -> Result<Self, DetectionError>
```

### from_file_path

```rust
pub async fn from_file_path(
    path: &str, 
    config: &DetectionConfig
) -> Result<Self, DetectionError>
```

## مثال الاستخدام

```rust
use batin::{FileType, DetectionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = DetectionConfig::default();
    let result = FileType::from_file_path("file.pdf", &config).await?;
    
    println!("النوع: {} ({:?})", result.extension, result.threat_level);
    Ok(())
}
```
