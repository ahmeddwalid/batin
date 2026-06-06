---
sidebar_position: 3
title: وحدة متعددي الصيغ
description: تعمق في تنفيذ كشف متعددي الصيغ
---

# تعمق في وحدة متعددي الصيغ

تحليل شامل لوحدة `src/detection/polyglot.rs`.

## الغرض

وحدة متعددي الصيغ تكشف الملفات **الصالحة في صيغ متعددة في نفس الوقت** - ناقل هجوم شائع.

## الخوارزمية الأساسية

```rust
pub fn detect_polyglot(data: &[u8], db: &SignatureDatabase) -> Result<Vec<String>> {
    let mut detected_formats = Vec::new();
    
    // فحص مواقع متعددة
    let check_offsets = [0, 512, 1024, 2048];
    
    for offset in check_offsets {
        if offset >= data.len() { break; }
        
        let slice = &data[offset..];
        let matches = db.match_signatures(slice);
        
        for (sig_idx, _) in matches {
            let format = db.signatures[sig_idx].extensions[0].clone();
            if !detected_formats.contains(&format) {
                detected_formats.push(format);
            }
        }
    }
    
    // حالة خاصة: PDF مع PE مضمن
    if data.starts_with(b"%PDF") {
        if let Some(pe_pos) = find_bytes(data, &[0x4D, 0x5A]) {
            if pe_pos > 100 {
                detected_formats.push("exe".to_string());
            }
        }
    }
    
    Ok(detected_formats)
}
```

## لماذا هذه المواقع؟

| الموقع | المبرر |
|--------|--------|
| 0 | موقع الرأس الأساسي |
| 512 | حجم قطاع الفلوبي |
| 1024 | موقع الرأس الثانوي |
| 2048 | حجم قطاع CD-ROM |

---

:::warning ملاحظة أمنية
ملفات متعددي الصيغ **مشبوهة دائماً**. أي ملف يُكتشف كصيغ متعددة يجب:

1. تسجيله
2. عزله أو حظره
3. مراجعته يدوياً
:::
