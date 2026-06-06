---
sidebar_position: 6
title: وحدة الأرشيف
description: تعمق في تنفيذ فحص الأرشيفات
---

# تعمق في وحدة الأرشيف

تحليل شامل لوحدة `src/io/archive.rs`.

## الغرض

وحدة الأرشيف توفر **استخراج وفحص آمن** للأرشيفات مع حدود أمان.

## حدود الأمان

```rust
const MAX_EXTRACTED_FILE_SIZE: u64 = 50_000_000;   // 50MB لكل ملف
const MAX_TOTAL_EXTRACTED_SIZE: u64 = 100_000_000; // 100MB إجمالي
const MAX_ARCHIVE_ENTRIES: usize = 10_000;         // الحد الأقصى للمدخلات
const SUSPICIOUS_COMPRESSION_RATIO: u64 = 100;     // كشف قنابل الضغط
```

## دالة الفحص

```rust
pub async fn scan_archive(
    data: &[u8],
    config: &DetectionConfig,
) -> Result<Vec<ArchiveEntry>>
```

## لماذا هذه الحدود؟

| الحد | المبرر |
|------|--------|
| حجم الملف | يمنع استنفاد الذاكرة |
| الحجم الإجمالي | يمنع ملء القرص |
| عدد المدخلات | يمنع هجمات O(n²) |
| نسبة الضغط | يكشف قنابل الضغط |

---

:::warning أمان الأرشيفات
الأرشيفات ناقل هجوم شائع:

- قنابل الضغط (ملفات صغيرة تتوسع لـ GB)
- ملفات تنفيذية مخفية
- حقن مسار الملف (`../../etc/passwd`)
:::
