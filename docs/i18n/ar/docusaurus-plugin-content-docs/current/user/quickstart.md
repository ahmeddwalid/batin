---
sidebar_position: 3
title: البداية السريعة
description: ابدأ مع باطن في 5 دقائق
---

# البداية السريعة

سيساعدك هذا الدليل على فحص الملفات في أقل من 5 دقائق.

## أول فحص لك

### فحص ملف واحد

```bash
batin scan suspicious.exe
```

**مثال على المخرجات:**

```
╭──────────────────────────────────────────────────────────────╮
│                         🔍 BATIN                              │
│          Security-Hardened File Type Detection               │
╰──────────────────────────────────────────────────────────────╯

╭─────────────────┬──────┬────────────┬───────────┬───────────╮
│ الملف           │ النوع │ الثقة      │ التهديد   │ التفاصيل  │
├─────────────────┼──────┼────────────┼───────────┼───────────┤
│ suspicious.exe  │ exe  │ 95%        │ ⚠ مشبوه   │ 📦 مضغوط  │
╰─────────────────┴──────┴────────────┴───────────┴───────────╯
```

### فهم المخرجات

| العمود | الوصف |
|--------|-------|
| **الملف** | مسار الملف الممسوح |
| **النوع** | نوع الملف المكتشف (بناءً على المحتوى، وليس الامتداد) |
| **الثقة** | مدى ثقة باطن في الكشف (0-100%) |
| **التهديد** | مستوى تقييم المخاطر |
| **التفاصيل** | علامات إضافية (مضغوط، مشفر، متعدد الصيغ، إلخ) |

### مستويات التهديد

| المستوى | الرمز | المعنى |
|---------|-------|--------|
| **آمن** | ✓ | لم يتم اكتشاف تهديدات |
| **مشبوه** | ⚠ | قد يكون خطيراً (مثل الملفات التنفيذية، السكربتات) |
| **خطير** | ⚠ | مخاطر عالية (مضغوط، متعدد الصيغ، أو تهديدات مضمنة) |
| **حرج** | ✖ | تهديد فوري (ماكرو تنفيذ تلقائي مكتشف) |

## فحص المجلدات

### الفحص التكراري

```bash
batin scan /path/to/directory --recursive
```

## تصفية النتائج

### عرض التهديدات فقط

```bash
batin scan /downloads --recursive --min-threat suspicious
```

### استبعاد الأنماط

```bash
batin scan /project --recursive --exclude "*.log" --exclude "node_modules/*"
```

## صيغ الإخراج

### إخراج JSON

```bash
batin scan file.pdf --json
```

### إخراج CSV

```bash
batin scan /directory --recursive --csv --output results.csv
```

## المراقبة في الوقت الحقيقي

مراقبة مجلد للملفات الجديدة:

```bash
batin watch /downloads
```

## الاستخدام كمكتبة

### الإضافة إلى Cargo.toml

```toml
[dependencies]
batin = "0.1"
tokio = { version = "1", features = ["full"] }
```

### الاستخدام الأساسي

```rust
use batin::{FileType, DetectionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = DetectionConfig::default();
    let result = FileType::from_file_path("test.pdf", &config).await?;
    
    println!("النوع: {}", result.extension);
    println!("MIME: {}", result.mime_type);
    println!("التهديد: {:?}", result.threat_level);
    
    Ok(())
}
```

---

:::tip الخطوات التالية

- تعرف على جميع خيارات CLI في [مرجع CLI](./cli-reference)
- استكشف [حالات الاستخدام](./use-cases) لأمثلة عملية
- افهم [مستويات التهديد](./threat-levels) بعمق
:::
