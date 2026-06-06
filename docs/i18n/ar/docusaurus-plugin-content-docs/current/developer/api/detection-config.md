---
sidebar_position: 2
title: DetectionConfig API
description: مرجع API لـ DetectionConfig struct
---

# مرجع DetectionConfig API

التوثيق الكامل لنوع `DetectionConfig`.

## التعريف

```rust
pub struct DetectionConfig {
    pub max_read_bytes: usize,
    pub enable_entropy: bool,
    pub enable_polyglot: bool,
    pub enable_embedded: bool,
    pub entropy_threshold: f64,
    pub timeout_ms: u64,
}
```

## الحقول

| الحقل | الافتراضي | الوصف |
|-------|----------|-------|
| `max_read_bytes` | 3072 | الحد الأقصى للبايتات المقروءة |
| `enable_entropy` | true | تمكين تحليل الإنتروبيا |
| `enable_polyglot` | true | تمكين كشف متعددي الصيغ |
| `enable_embedded` | true | تمكين فحص التهديدات المضمنة |
| `entropy_threshold` | 7.2 | عتبة كشف المعبأ |
| `timeout_ms` | 30000 | مهلة تحليل الملف |

## الاستخدام

```rust
// التكوين الافتراضي
let config = DetectionConfig::default();

// تكوين مخصص
let config = DetectionConfig {
    max_read_bytes: 8192,
    enable_entropy: true,
    enable_polyglot: true,
    enable_embedded: true,
    entropy_threshold: 7.5,
    timeout_ms: 60000,
};
```

## أمثلة التكوين

### السرعة القصوى

```rust
let config = DetectionConfig {
    max_read_bytes: 1024,
    enable_entropy: false,
    enable_polyglot: false,
    enable_embedded: false,
    ..Default::default()
};
```

### الأمان الأقصى

```rust
let config = DetectionConfig {
    max_read_bytes: 10240,
    enable_entropy: true,
    enable_polyglot: true,
    enable_embedded: true,
    entropy_threshold: 7.0,  // أكثر حساسية
    ..Default::default()
};
```
