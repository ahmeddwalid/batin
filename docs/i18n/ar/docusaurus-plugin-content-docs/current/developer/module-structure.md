---
sidebar_position: 3
title: هيكل الوحدات
description: فهم تنظيم قاعدة كود باطن
---

# هيكل الوحدات

دليل لتنظيم الكود المصدري لباطن ومسؤوليات الوحدات.

## تخطيط المجلدات

```
src/
├── lib.rs              # نقطة دخول المكتبة، الأنواع الأساسية
├── main.rs             # نقطة دخول الـ CLI الثنائي
├── utils.rs            # وظائف المرافق المشتركة
│
├── detection/          # كشف نوع الملف
│   ├── mod.rs          # تصدير الوحدة
│   ├── signatures.rs   # قاعدة بيانات البايتات السحرية
│   ├── entropy.rs      # حسابات الإنتروبيا
│   ├── polyglot.rs     # كشف الصيغ المتعددة
│   └── embedded.rs     # فحص التهديدات المضمنة
│
├── analysis/           # تحليل الملفات العميق
│   ├── mod.rs          # تصدير الوحدة
│   ├── validation.rs   # التحقق من البنية
│   ├── forensics.rs    # تصنيف الأجزاء
│   └── binary.rs       # تحليل PE/ELF/Mach-O
│
├── io/                 # عمليات الإدخال/الإخراج
│   ├── mod.rs          # تصدير الوحدة
│   ├── batch.rs        # معالجة الملفات المتوازية
│   ├── archive.rs      # استخراج الأرشيفات
│   └── hasher.rs       # تجزئة الملفات
│
└── cli/                # واجهة سطر الأوامر
    ├── mod.rs          # تصدير وحدة CLI
    ├── scanner.rs      # أمر الفحص
    ├── watcher.rs      # أمر المراقبة
    └── console.rs      # تنسيق الطرفية
```

---

## الوحدة الأساسية: `lib.rs`

### المسؤوليات

1. **تعريف الأنواع الأساسية** (`FileType`، `DetectionConfig`، `ThreatLevel`)
2. **واجهة الكشف الرئيسية** (`from_bytes`، `from_file_path`)
3. **إعادة تصدير** العناصر العامة من الوحدات الفرعية
4. **أنواع الأخطاء** (`DetectionError`)

### أقسام الكود الرئيسية

```rust
// أنواع الأخطاء
#[derive(Error, Debug)]
pub enum DetectionError {
    Io(#[from] std::io::Error),
    FileTooLarge(u64, u64),
    CorruptedStructure(String),
    Timeout(u64),
    Unsupported,
}

// التكوين
pub struct DetectionConfig {
    pub max_read_bytes: usize,
    pub enable_entropy: bool,
    pub enable_polyglot: bool,
    pub enable_embedded: bool,
    pub entropy_threshold: f64,
    pub timeout_ms: u64,
}

// نوع النتيجة الرئيسي
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

---

## وحدة الكشف

### `signatures.rs`

**الغرض:** قاعدة بيانات توقيعات البايتات السحرية

**المكونات الرئيسية:**

```rust
// قاعدة بيانات عامة آمنة للخيوط
pub static SIGNATURE_DB: LazyLock<RwLock<SignatureDatabase>>

// تعريف التوقيع
pub struct FileSignature {
    pub magic: &'static [u8],          // البايتات السحرية
    pub offset: usize,                  // الموقع في الملف
    pub additional_magic: Option<...>,  // التحقق الثانوي
    pub extensions: Vec<String>,        // امتدادات الملفات
    pub mime_type: &'static str,        // نوع MIME
    pub category: FileCategory,         // التصنيف
}

// قاعدة بيانات بأكثر من 60 صيغة
pub struct SignatureDatabase {
    pub signatures: Vec<FileSignature>,
    pub extension_map: HashMap<String, Vec<usize>>,
}
```

### `entropy.rs`

**الغرض:** حسابات إنتروبيا شانون واختبار كاي مربع

**الوظائف الرئيسية:**

```rust
// إحصائيات المرور الواحد
pub fn calculate_entropy_stats(data: &[u8]) -> EntropyStats

// التحليل الشامل
pub fn analyze_entropy(
    data: &[u8], 
    packed_threshold: f64
) -> Result<EntropyProfile>
```

### `polyglot.rs`

**الغرض:** كشف الملفات الصالحة في صيغ متعددة

### `embedded.rs`

**الغرض:** فحص المحتوى الخبيث المضمن

---

## وحدة التحليل

### `validation.rs`

**الغرض:** التحقق من بنية الملف بعد البايتات السحرية

### `forensics.rs`

**الغرض:** تصنيف أجزاء الملفات بدون رؤوس

### `binary.rs`

**الغرض:** استخراج البيانات الوصفية من الملفات التنفيذية

---

## وحدة الإدخال/الإخراج

### `batch.rs`

**الغرض:** معالجة الملفات المتوازية

### `archive.rs`

**الغرض:** استخراج وفحص الأرشيفات بأمان

### `hasher.rs`

**الغرض:** حساب تجزئة الملفات

---

## وحدة CLI

### `scanner.rs`

**الغرض:** تنفيذ أمر `batin scan`

### `watcher.rs`

**الغرض:** تنفيذ أمر `batin watch`

### `console.rs`

**الغرض:** تنسيق الطرفية وتنسيق الإخراج

---

## علامات الميزات

```toml
[features]
default = ["full"]
full = ["hashing", "binary-parsing", "archive", "cli"]

hashing = ["md-5", "sha2"]        # io/hasher.rs
binary-parsing = ["goblin"]       # analysis/binary.rs
archive = ["zip", "tar", "flate2"]# io/archive.rs
cli = ["clap", "colored", ...]    # cli/*
```

**لماذا الميزات الاختيارية؟**

- ملف ثنائي أصغر للاستخدام كمكتبة فقط
- اعتماديات أقل عندما لا تكون مطلوبة
- ترجمة أسرع للميزات الأساسية

---

:::tip نصيحة للمساهمين
عند إضافة وظائف جديدة:

1. **منطق الكشف** → وحدة `detection/`
2. **التحليل العميق** → وحدة `analysis/`
3. **إدخال/إخراج الملفات** → وحدة `io/`
4. **أوامر CLI** → وحدة `cli/`
5. **المرافق المشتركة** → `utils.rs`
:::
