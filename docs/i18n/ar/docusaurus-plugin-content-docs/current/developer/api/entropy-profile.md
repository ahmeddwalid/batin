---
sidebar_position: 3
title: EntropyProfile API
description: مرجع API لـ EntropyProfile struct
---

# مرجع EntropyProfile API

التوثيق الكامل لنوع `EntropyProfile`.

## التعريف

```rust
#[derive(Debug, Clone, Serialize)]
pub struct EntropyProfile {
    pub global_entropy: f64,
    pub block_entropies: Vec<f64>,
    pub chi_square: f64,
    pub is_packed: bool,
    pub is_encrypted: bool,
}
```

## الحقول

| الحقل | النوع | الوصف |
|-------|-------|-------|
| `global_entropy` | `f64` | إنتروبيا الملف الكلية (0.0-8.0) |
| `block_entropies` | `Vec<f64>` | إنتروبيا لكل بلوك |
| `chi_square` | `f64` | إحصائية كاي مربع |
| `is_packed` | `bool` | هل الملف معبأ |
| `is_encrypted` | `bool` | هل الملف مشفر |

## تفسير الإنتروبيا

| النطاق | المعنى |
|--------|--------|
| 0.0-3.0 | بيانات متكررة جداً |
| 3.0-5.0 | نص أو كود مصدر |
| 5.0-6.5 | كود مترجم عادي |
| 6.5-7.5 | بيانات مضغوطة |
| 7.5-8.0 | مشفر أو معبأ |

## تفسير كاي مربع

| القيمة | المعنى |
|--------|--------|
| < 50 | منتظم جداً (مشفر) |
| 50-150 | منتظم (مضغوط) |
| 150-500 | تباين طبيعي |
| > 500 | غير منتظم (نص) |
