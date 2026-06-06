---
sidebar_position: 9
title: التكوين
description: تكوين سلوك الكشف في باطن
---

# التكوين

تخصيص سلوك الكشف في باطن لحالة استخدامك.

## DetectionConfig

هيكل `DetectionConfig` يتحكم في جميع معلمات الكشف.

```rust
use batin::DetectionConfig;

let config = DetectionConfig {
    max_read_bytes: 3072,               // البايتات للقراءة للكشف
    enable_entropy: true,                // تفعيل تحليل الإنتروبيا
    enable_polyglot: true,               // تفعيل كشف متعددي الصيغ
    enable_embedded: true,               // فحص التهديدات المضمنة
    entropy_threshold: 7.2,              // عتبة كشف المضغوط
    packed_chi_square_threshold: 100.0,  // عتبة Chi-square للضغط
    encrypted_entropy_threshold: 7.8,    // عتبة كشف التشفير
    encrypted_chi_square_threshold: 50.0,// Chi-square للتشفير
    timeout_ms: 5000,                    // مهلة قراءة الملف
};
```

## خيارات التكوين

### max_read_bytes

الحد الأقصى للبايتات لقراءتها من كل ملف لكشف التوقيع.

| القيمة | حالة الاستخدام |
|--------|---------------|
| `1024` | فحوصات سريعة، تقليل I/O |
| `3072` | **الافتراضي** - متوازن |
| `8192` | دقة أفضل للصيغ المعقدة |
| `65536` | تحليل عميق، أبطأ |

### enable_entropy

تبديل تحليل إنتروبيا شانون.

- **`true` (الافتراضي)**: حساب الإنتروبيا، كشف المضغوط/المشفر
- **`false`**: تخطي تحليل الإنتروبيا (أسرع)

### enable_polyglot

تبديل كشف الصيغ المتعددة.

- **`true` (الافتراضي)**: فحص إزاحات متعددة للصيغ المخفية
- **`false`**: كشف التوقيع الأساسي فقط

### enable_embedded

تبديل فحص التهديدات المضمنة.

- **`true` (الافتراضي)**: فحص الماكرو، JavaScript، الملفات التنفيذية
- **`false`**: تخطي تحليل المحتوى المضمن

---

## تكوينات مسبقة

### فحص سريع

```rust
let fast_config = DetectionConfig {
    max_read_bytes: 1024,
    enable_entropy: false,
    enable_polyglot: false,
    enable_embedded: false,
    timeout_ms: 1000,
    ..Default::default()
};
```

### التركيز على الأمان

```rust
let security_config = DetectionConfig {
    max_read_bytes: 8192,
    enable_entropy: true,
    enable_polyglot: true,
    enable_embedded: true,
    entropy_threshold: 7.0,  // عتبة أقل (أكثر حساسية)
    timeout_ms: 10000,
    ..Default::default()
};
```

### التحليل الجنائي

```rust
let forensic_config = DetectionConfig {
    max_read_bytes: 65536,  // قراءة المزيد من البيانات
    enable_entropy: true,
    enable_polyglot: true,
    enable_embedded: true,
    timeout_ms: 30000,      // السماح بمزيد من الوقت
    ..Default::default()
};
```

---

## متغيرات البيئة

| المتغير | المكافئ في CLI | الوصف |
|---------|---------------|-------|
| `BATIN_MAX_READ_BYTES` | غ/م | الحد الأقصى الافتراضي للبايتات |
| `BATIN_TIMEOUT_MS` | غ/م | المهلة الافتراضية |
| `NO_COLOR` | غ/م | تعطيل الإخراج الملون |
| `RUST_LOG` | `--verbose` | مستوى السجل |

```bash
# مثال: زيادة البايتات المقروءة لجميع الفحوصات
export BATIN_MAX_READ_BYTES=8192
batin scan /directory -r
```
