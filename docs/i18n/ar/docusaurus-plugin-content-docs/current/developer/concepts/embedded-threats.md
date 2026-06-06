---
sidebar_position: 4
title: التهديدات المضمنة
description: كشف المحتوى الخبيث المضمن
---

# كشف التهديدات المضمنة

كيف يفحص باطن المحتوى الخبيث المخفي داخل الملفات.

## نظرة عامة

العديد من صيغ الملفات يمكنها **احتواء** محتوى آخر:

- مستندات Office → ماكرو VBA
- ملفات PDF → JavaScript
- الأرشيفات → ملفات تنفيذية
- الصور → بيانات مخفية

المرحلة 4 في باطن تفحص هذه التهديدات المضمنة.

---

## أنواع التهديدات

```rust
pub enum ThreatType {
    Macro,      // ماكرو Office VBA
    JavaScript, // PDF/HTML JavaScript
    Executable, // EXE/DLL مخفي
    Script,     // سكربتات Shell/PowerShell
    Unknown,    // تهديد غير مصنف
}
```

---

## كشف ماكرو Office

### التهديد

ماكرو VBA في مستندات Office يمكنه:

- تحميل وتنفيذ برمجيات خبيثة
- سرقة بيانات الاعتماد/البيانات
- تشفير الملفات (فيروسات الفدية)
- الانتشار إلى مستندات أخرى

### ماكرو التنفيذ التلقائي (حرج)

الأكثر خطورة—يعمل تلقائياً عند فتح المستند:

| اسم الماكرو | المحفز |
|------------|--------|
| `AutoOpen` | فتح المستند |
| `AutoExec` | بدء التطبيق |
| `Document_Open` | فتح مستند Word |
| `Workbook_Open` | فتح مصنف Excel |

### تنفيذ الكشف

```rust
fn detect_macros(data: &[u8]) -> Vec<EmbeddedThreat> {
    let mut threats = Vec::new();
    
    // علامات التنفيذ التلقائي (شدة حرجة)
    let auto_exec_markers: [&[u8]; 4] = [
        b"AutoOpen",
        b"AutoExec", 
        b"Document_Open",
        b"Workbook_Open"
    ];
    
    for marker in &auto_exec_markers {
        if let Some(offset) = find_bytes(data, marker) {
            threats.push(EmbeddedThreat {
                threat_type: ThreatType::Macro,
                offset,
                severity: ThreatLevel::Critical,
                description: format!(
                    "ماكرو تنفيذ تلقائي مكتشف: {}",
                    String::from_utf8_lossy(marker)
                ),
            });
        }
    }
    
    // علامات VBA العادية (فقط إذا لم يُعثر على تنفيذ تلقائي)
    if threats.is_empty() {
        let macro_markers: [&[u8]; 3] = [
            b"VBA",
            b"_VBA_PROJECT",
            b"macros/"
        ];
        
        for marker in &macro_markers {
            if let Some(offset) = find_bytes(data, marker) {
                threats.push(EmbeddedThreat {
                    threat_type: ThreatType::Macro,
                    offset,
                    severity: ThreatLevel::Dangerous,
                    description: "ماكرو Office مكتشف".to_string(),
                });
                break;
            }
        }
    }
    
    threats
}
```

---

## كشف JavaScript في PDF

### التهديد

JavaScript في PDF يمكنه:

- استغلال ثغرات قارئ PDF
- تحميل برمجيات خبيثة
- إعادة التوجيه لمواقع تصيد
- العمل عند فتح المستند

### تنفيذ الكشف

```rust
fn detect_pdf_javascript(data: &[u8]) -> Vec<EmbeddedThreat> {
    let mut threats = Vec::new();
    
    // علامات كائن JavaScript في PDF
    let js_markers: [&[u8]; 2] = [
        b"/JavaScript",
        b"/JS"
    ];
    
    for marker in &js_markers {
        if let Some(offset) = find_bytes(data, marker) {
            threats.push(EmbeddedThreat {
                threat_type: ThreatType::JavaScript,
                offset,
                severity: ThreatLevel::Suspicious,
                description: "PDF مع JavaScript مكتشف".to_string(),
            });
            break;
        }
    }
    
    threats
}
```

---

## كشف الملفات التنفيذية في الأرشيفات

### التهديد

المهاجمون يخفون الملفات التنفيذية في الأرشيفات لـ:

- تجاوز فلاتر البريد
- خداع المستخدمين بامتدادات مزيفة
- تجميع مكونات متعددة للبرمجيات الخبيثة

### تنفيذ الكشف

```rust
fn detect_executable_in_archive(data: &[u8]) -> Vec<EmbeddedThreat> {
    let mut threats = Vec::new();
    
    // البحث عن رأس PE (MZ) في بيانات الأرشيف
    if let Some(offset) = find_bytes(data, &[0x4D, 0x5A]) {
        threats.push(EmbeddedThreat {
            threat_type: ThreatType::Executable,
            offset,
            severity: ThreatLevel::Dangerous,
            description: "ملف تنفيذي في الأرشيف".to_string(),
        });
    }
    
    threats
}
```

---

## مصفوفة الشدة

| الفئة | التهديد | الشدة |
|-------|---------|-------|
| مستند | ماكرو AutoOpen/AutoExec | **حرج** |
| مستند | ماكرو VBA عادي | خطير |
| PDF | JavaScript | مشبوه |
| أرشيف | ملف تنفيذي مضمن | خطير |

---

## هيكل EmbeddedThreat

```rust
#[derive(Debug, Clone, Serialize)]
pub struct EmbeddedThreat {
    /// نوع التهديد المضمن
    pub threat_type: ThreatType,
    
    /// موقع البايت حيث وُجد التهديد
    pub offset: usize,
    
    /// تقييم الشدة
    pub severity: ThreatLevel,
    
    /// وصف قابل للقراءة
    pub description: String,
}
```

---

:::tip أفضل الممارسات الأمنية
عند معالجة الملفات المرفوعة:

1. **افحص دائماً** التهديدات المضمنة
2. **احظر** الشدة الحرجة (ماكرو التنفيذ التلقائي)
3. **اعزل** الشدة الخطيرة للمراجعة
4. **سجل** الشدة المشبوهة للمراقبة
:::
