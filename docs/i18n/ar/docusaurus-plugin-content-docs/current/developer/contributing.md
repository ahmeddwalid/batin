---
sidebar_position: 1
title: دليل المساهمة
description: كيفية المساهمة في باطن
---

# المساهمة في باطن

شكراً لاهتمامك بالمساهمة في باطن! يشرح هذا الدليل كيفية البدء.

## إعداد التطوير

### المتطلبات الأساسية

- **Rust 1.75+** (rustup موصى به)
- **Git** للتحكم في الإصدارات
- **Cargo** للبناء والاختبار

### الاستنساخ والبناء

```bash
# استنساخ المستودع
git clone https://github.com/ahmeddwalid/batin.git
cd batin

# البناء في وضع التصحيح
cargo build

# تشغيل الاختبارات
cargo test --all-features

# تشغيل فحوصات clippy
cargo clippy --all-features -- -D warnings

# التحقق من التنسيق
cargo fmt --all -- --check
```

---

## سير عمل المساهمة

### 1. البحث عن مشكلة

- تصفح [المشاكل المفتوحة](https://github.com/ahmeddwalid/batin/issues)
- ابحث عن تسميات `good first issue`
- أو افتح مشكلة جديدة لمناقشة فكرتك

### 2. Fork وإنشاء فرع

```bash
# Fork على GitHub، ثم استنسخ نسختك
git clone https://github.com/YOUR_USERNAME/batin.git
cd batin

# إنشاء فرع للميزة
git checkout -b feature/your-feature-name
```

### 3. إجراء التغييرات

- اتبع أسلوب الكود (شغل `cargo fmt`)
- أضف اختبارات للوظائف الجديدة
- حدث التوثيق إذا لزم الأمر
- شغل مجموعة الاختبارات الكاملة

### 4. Commit

```bash
git add .
git commit -m "feat: add support for XYZ format"
```

**تنسيق رسائل Commit:**

- `feat:` - ميزة جديدة
- `fix:` - إصلاح خطأ
- `docs:` - توثيق فقط
- `test:` - إضافة اختبارات
- `refactor:` - إعادة هيكلة الكود
- `perf:` - تحسين الأداء

### 5. Push وفتح PR

```bash
git push origin feature/your-feature-name
```

ثم افتح Pull Request على GitHub.

---

## إضافة توقيعات ملفات جديدة

### الخطوة 1: البحث

1. ابحث عن مواصفات الصيغة
2. حدد البايتات السحرية والموقع
3. تحقق من الصيغ المشابهة التي تحتاج تمييز

### الخطوة 2: إضافة التوقيع

في `src/detection/signatures.rs`:

```rust
FileSignature {
    magic: &[0x00, 0x00, 0x01, 0x00],
    offset: 0,
    additional_magic: None,
    extensions: vec!["ico".to_string()],
    mime_type: "image/x-icon",
    category: FileCategory::Image,
},
```

### الخطوة 3: إضافة اختبار

```rust
#[test]
fn test_detect_ico() {
    let ico_data = include_bytes!("../test_files/sample.ico");
    let db = SignatureDatabase::default();
    let matches = db.match_signatures(ico_data);
    assert!(!matches.is_empty());
}
```

---

## قائمة التحقق من Pull Request

- [ ] الكود يترجم بدون تحذيرات
- [ ] جميع الاختبارات تنجح
- [ ] `cargo clippy` ينجح
- [ ] `cargo fmt --check` ينجح
- [ ] الكود الجديد له اختبارات
- [ ] التوثيق محدث

---

## الحصول على المساعدة

- **أسئلة؟** افتح [نقاش](https://github.com/ahmeddwalid/batin/discussions)
- **وجدت خطأ؟** افتح [مشكلة](https://github.com/ahmeddwalid/batin/issues)
- **مشكلة أمنية؟** راجع [SECURITY.md](https://github.com/ahmeddwalid/batin/blob/main/SECURITY.md)

---

:::tip أول مرة تساهم؟
ابحث عن المشاكل المصنفة `good first issue` - تم اختيارها خصيصاً لتكون سهلة للمساهمين الجدد!
:::
