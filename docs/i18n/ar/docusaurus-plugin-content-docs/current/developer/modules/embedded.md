---
sidebar_position: 4
title: وحدة المضمن
description: تعمق في تنفيذ كشف التهديدات المضمنة
---

# تعمق في وحدة المضمن

تحليل شامل لوحدة `src/detection/embedded.rs`.

## الغرض

وحدة المضمن تفحص **المحتوى الخبيث المخفي** داخل الملفات:

- ماكرو Office VBA
- JavaScript في PDF
- ملفات تنفيذية في الأرشيفات

## دالة الفحص الرئيسية

```rust
pub fn scan_embedded_content(
    data: &[u8],
    signature: &FileSignature,
) -> Result<Vec<EmbeddedThreat>> {
    let mut threats = Vec::new();
    
    match signature.category {
        FileCategory::Document => {
            if signature.mime_type.contains("msword") {
                threats.extend(detect_macros(data));
            }
            if signature.mime_type == "application/pdf" {
                threats.extend(detect_pdf_javascript(data));
            }
        }
        FileCategory::Archive => {
            threats.extend(detect_executable_in_archive(data));
        }
        _ => {}
    }
    
    Ok(threats)
}
```

## أنواع التهديدات

| النوع | الوصف | الشدة |
|-------|-------|-------|
| `Macro` | VBA، AutoOpen | حرج/خطير |
| `JavaScript` | /JS، /JavaScript | مشبوه |
| `Executable` | رأس MZ في أرشيف | خطير |

---

:::tip أفضل الممارسات

- **احظر** الماكرو ذات الشدة الحرجة (AutoOpen)
- **اعزل** التهديدات الخطيرة للمراجعة
- **سجل** التهديدات المشبوهة للمراقبة
:::
