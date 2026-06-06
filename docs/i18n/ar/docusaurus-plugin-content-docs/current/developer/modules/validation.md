---
sidebar_position: 5
title: وحدة التحقق
description: تعمق في تنفيذ التحقق من بنية الملفات
---

# تعمق في وحدة التحقق

تحليل شامل لوحدة `src/analysis/validation.rs`.

## الغرض

وحدة التحقق **تتحقق من بنية الملفات بعد البايتات السحرية** لزيادة دقة الكشف.

## دوال التحقق

```rust
pub fn validate_pdf(data: &[u8]) -> ValidationResult
pub fn validate_png(data: &[u8]) -> ValidationResult
pub fn validate_zip(data: &[u8]) -> ValidationResult
pub fn validate_pe(data: &[u8]) -> ValidationResult
```

## مثال: التحقق من PDF

```rust
pub fn validate_pdf(data: &[u8]) -> ValidationResult {
    // التحقق من الرأس
    if &data[0..5] != b"%PDF-" {
        return ValidationResult { is_valid: false, .. };
    }
    
    // التحقق من علامة EOF
    let has_eof = find_pattern_reverse(data, b"%%EOF").is_some();
    
    // التحقق من جدول xref
    let has_xref = find_pattern(data, b"xref").is_some();
    
    ValidationResult {
        is_valid: has_eof && has_xref,
        confidence_boost: 0.1,
        details: "بنية PDF صالحة".to_string(),
    }
}
```

---

:::tip لماذا التحقق؟
مطابقة البايتات السحرية وحدها يمكن تزويرها. التحقق من البنية:

- يزيد دقة الكشف
- يكشف الملفات المقطوعة أو الفاسدة
- يميز الصيغ المتشابهة
:::
