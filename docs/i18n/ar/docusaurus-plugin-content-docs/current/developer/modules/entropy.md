---
sidebar_position: 2
title: وحدة الإنتروبيا
description: تعمق في تنفيذ حساب الإنتروبيا
---

# تعمق في وحدة الإنتروبيا

تحليل شامل لوحدة `src/detection/entropy.rs`.

## الغرض

وحدة الإنتروبيا توفر **تحليل نظرية المعلومات** لمحتوى الملفات:

- حساب إنتروبيا شانون
- اختبار كاي مربع الإحصائي
- كشف المحتوى المعبأ/المشفر
- تصور الإنتروبيا بلوكات

## هياكل البيانات الرئيسية

### EntropyStats

```rust
pub struct EntropyStats {
    pub frequency: [usize; 256],  // توزيع تردد البايتات
    pub entropy: f64,             // إنتروبيا شانون (0-8 بت)
    pub chi_square: f64,          // إحصائية كاي مربع
}
```

### EntropyProfile

```rust
#[derive(Debug, Clone, Serialize)]
pub struct EntropyProfile {
    pub global_entropy: f64,      // إنتروبيا الملف الكلية
    pub block_entropies: Vec<f64>, // إنتروبيا لكل بلوك
    pub chi_square: f64,          // الانتظام الإحصائي
    pub is_packed: bool,          // علامة ملف تنفيذي معبأ
    pub is_encrypted: bool,       // علامة تشفير
}
```

---

## الخوارزمية الأساسية: حساب المرور الواحد

```rust
pub fn calculate_entropy_stats(data: &[u8]) -> EntropyStats {
    if data.is_empty() {
        return EntropyStats::default();
    }
    
    // مرور واحد: بناء التردد
    let mut frequency: [usize; 256] = [0; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }
    
    // استخراج كلا المقياسين من جدول التردد
    let len = data.len() as f64;
    let mut entropy = 0.0;
    let mut chi_square = 0.0;
    let expected = len / 256.0;
    
    for &count in &frequency {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();  // معادلة شانون
            
            let diff = count as f64 - expected;
            chi_square += (diff * diff) / expected;  // كاي مربع
        }
    }
    
    EntropyStats { frequency, entropy, chi_square }
}
```

---

## كشف المعبأ مقابل المشفر

```rust
pub fn analyze_entropy(data: &[u8], packed_threshold: f64) -> Result<EntropyProfile> {
    let stats = calculate_entropy_stats(data);
    
    Ok(EntropyProfile {
        global_entropy: stats.entropy,
        chi_square: stats.chi_square,
        is_packed: stats.entropy > packed_threshold && stats.chi_square < 100.0,
        is_encrypted: stats.entropy > 7.8 && stats.chi_square < 50.0,
        ..
    })
}
```

### لماذا كلا المقياسين؟

**ملفات معبأة** (UPX، Themida):

- إنتروبيا عالية (مضغوطة)
- كاي مربع معتدل (ليست عشوائية تماماً)

**ملفات مشفرة** (AES، فيروسات الفدية):

- إنتروبيا عالية جداً (~8.0)
- كاي مربع منخفض جداً (توزيع منتظم)

---

:::tip نصائح الأداء

1. **تخطي الملفات الصغيرة**: الإنتروبيا لا معنى لها لـ < 256 بايت
2. **استخدم `calculate_entropy_stats`**: للحصول على كلا المقياسين مرة واحدة
3. **تخزين النتائج مؤقتاً**: حساب الإنتروبيا حتمي

:::
