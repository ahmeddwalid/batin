---
sidebar_position: 4
title: أنواع التهديدات API
description: مرجع API لتعدادات التهديدات
---

# مرجع أنواع التهديدات API

التوثيق الكامل لتعدادات التهديدات.

## ThreatLevel

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Safe,       // 0 - لا خطر
    Suspicious, // 1 - مشبوه قليلاً
    Dangerous,  // 2 - خطير
    Critical,   // 3 - حرج
}
```

## ThreatType

```rust
pub enum ThreatType {
    Macro,      // ماكرو Office VBA
    JavaScript, // PDF/HTML JavaScript
    Executable, // EXE/DLL مخفي
    Script,     // سكربتات Shell/PowerShell
    Unknown,    // تهديد غير مصنف
}
```

## EmbeddedThreat

```rust
#[derive(Debug, Clone, Serialize)]
pub struct EmbeddedThreat {
    pub threat_type: ThreatType,
    pub offset: usize,
    pub severity: ThreatLevel,
    pub description: String,
}
```

## مثال الاستخدام

```rust
use batin::{FileType, DetectionConfig, ThreatLevel};

async fn check_file(path: &str) -> Result<(), String> {
    let config = DetectionConfig::default();
    let result = FileType::from_file_path(path, &config).await
        .map_err(|e| e.to_string())?;
    
    match result.threat_level {
        ThreatLevel::Safe => println!("✅ آمن"),
        ThreatLevel::Suspicious => println!("⚠️ مشبوه"),
        ThreatLevel::Dangerous => println!("🔴 خطير"),
        ThreatLevel::Critical => println!("🚨 حرج"),
    }
    
    Ok(())
}
```
