---
sidebar_position: 5
title: صيغ الإخراج
description: فهم صيغ إخراج باطن
---

# صيغ الإخراج

يدعم باطن ثلاث صيغ إخراج: الجدول (الافتراضي)، JSON، و CSV.

## إخراج الجدول (الافتراضي)

```bash
batin scan /uploads --recursive
```

```
╭─────────────────┬──────┬────────────┬───────────┬───────────╮
│ الملف           │ النوع │ الثقة      │ التهديد   │ التفاصيل  │
├─────────────────┼──────┼────────────┼───────────┼───────────┤
│ invoice.pdf     │ pdf  │ 95%        │ ✓ آمن     │           │
│ packed.exe      │ exe  │ 92%        │ ⚠ خطير   │ 📦 مضغوط  │
│ document.docx   │ docx │ 90%        │ ✖ حرج    │ 📎 ماكرو   │
╰─────────────────┴──────┴────────────┴───────────┴───────────╯
```

## إخراج JSON

### الاستخدام الأساسي

```bash
batin scan file.pdf --json
```

### مخرج JSON كامل

```json
[
  {
    "path": "/uploads/file.pdf",
    "file_type": {
      "extension": "pdf",
      "mime_type": "application/pdf",
      "confidence": 0.95,
      "threat_level": "Safe",
      "detected_formats": ["pdf"],
      "embedded_threats": [],
      "entropy_profile": {
        "global_entropy": 4.23,
        "is_packed": false,
        "is_encrypted": false
      }
    }
  }
]
```

### معالجة JSON باستخدام jq

```bash
# استخراج ملخص
batin scan /dir -r --json | jq '.[] | {file: .path, type: .file_type.extension, threat: .file_type.threat_level}'

# تصفية غير الآمنة
batin scan /dir -r --json | jq '[.[] | select(.file_type.threat_level != "Safe")]'

# العد حسب النوع
batin scan /dir -r --json | jq 'group_by(.file_type.extension) | map({type: .[0].file_type.extension, count: length})'

# العد حسب التهديد
batin scan /dir -r --json | jq 'group_by(.file_type.threat_level) | map({level: .[0].file_type.threat_level, count: length})'
```

## إخراج CSV

### الاستخدام الأساسي

```bash
batin scan /uploads -r --csv --output results.csv
```

### صيغة CSV

```csv
path,extension,mime_type,confidence,threat_level,detected_formats,is_packed,is_encrypted
/uploads/file.pdf,pdf,application/pdf,0.95,Safe,"[""pdf""]",false,false
/uploads/packed.exe,exe,application/x-dosexec,0.92,Dangerous,"[""exe""]",true,false
```

### معالجة CSV

```bash
# استيراد في جدول بيانات
batin scan /dir -r --csv | column -t -s,

# تصفية بـ awk
batin scan /dir -r --csv | awk -F',' '$5 != "Safe" {print $1, $5}'

# التكامل مع قاعدة البيانات
batin scan /evidence -r --csv --output - | sqlite3 evidence.db ".import /dev/stdin scans"
```

---

## اختيار الصيغة

| حالة الاستخدام | الصيغة | السبب |
|---------------|-------|-------|
| الفحص اليدوي | جدول | سهل القراءة |
| الأتمتة | JSON | قابل للتحليل، مفصل |
| جداول البيانات | CSV | استيراد Excel/Sheets |
| التكامل مع SIEM | JSON | معيار الصناعة |
