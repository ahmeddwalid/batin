---
sidebar_position: 8
title: الطب الشرعي الرقمي
description: استخدام باطن في التحقيقات الجنائية الرقمية
---

# الطب الشرعي الرقمي

دليل للمحققين الجنائيين الرقميين الذين يستخدمون باطن.

## أفضل ممارسات جمع الأدلة

### مبادئ أساسية

1. **سلامة الأدلة**: لا تعدل البيانات الأصلية أبداً
2. **سلسلة الحراسة**: وثق كل وصول
3. **قابلية التكرار**: النتائج يجب أن تكون قابلة للتحقق
4. **التوثيق الشامل**: سجل كل شيء

### سير العمل

```mermaid
flowchart LR
    A[الحصول على الصورة] --> B[التحقق من الهاش]
    B --> C[فحص باطن]
    C --> D[التحليل]
    D --> E[التوثيق]
```

---

## فحص صورة القرص

```bash
# تثبيت الصورة للقراءة فقط
sudo mount -o ro,loop,noexec evidence.dd /mnt/evidence

# فحص شامل مع الهاشات
batin scan /mnt/evidence -r --json --hash \
  --output case-$(date +%Y%m%d)-scan.json

# إنشاء ملخص
jq '.[] | {path: .path, type: .file_type.extension, threat: .file_type.threat_level, sha256: .file_type.hashes.sha256}' case-*.json
```

---

## تصنيف الأجزاء

باطن يمكنه تحديد أنواع الملفات حتى بدون رؤوس كاملة.

### حالات الاستخدام

- **نحت البيانات**: تحديد الملفات من مساحة غير مخصصة
- **الملفات التالفة**: تصنيف البيانات الجزئية
- **تحليل الذاكرة**: تحديد المحتوى في تفريغات الذاكرة

```bash
# فحص الأجزاء المنحوتة
batin scan /carved-files -r --json --min-threat safe
```

---

## كشف انتحال الامتداد

الملفات ذات الامتدادات المضللة قد تشير إلى:

- إخفاء البيانات
- نشاط ضار
- تلاعب المستخدم

```bash
# إيجاد عدم تطابق الامتداد
batin scan /evidence -r --json | jq '
  .[] | 
  select(
    (.path | split(".") | last) != .file_type.extension
  ) | 
  {
    path: .path, 
    claimed: (.path | split(".") | last), 
    actual: .file_type.extension
  }
'
```

---

## إعادة بناء الجدول الزمني

### جمع البيانات الوصفية

```bash
# إنشاء تقرير بالطوابع الزمنية
find /mnt/evidence -type f -printf '%T+ %p\n' | sort > timeline.txt

# إضافة معلومات باطن
batin scan /mnt/evidence -r --json --hash > batin-results.json

# دمج البيانات
python3 merge-timeline.py timeline.txt batin-results.json > full-timeline.json
```

---

## سلسلة الحراسة

### توثيق الفحص

```bash
# حساب هاش التقرير نفسه
sha256sum case-*-scan.json >> chain-of-custody.txt

# تسجيل تفاصيل الفحص
echo "$(date -Iseconds) | المحقق: $USER | الأداة: batin $(batin --version)" >> chain-of-custody.txt
```

### تنسيق التقرير

```json
{
  "case_id": "2024-001",
  "examiner": "اسم المحقق",
  "date": "2024-01-15T10:30:00Z",
  "evidence_hash": "sha256:abc123...",
  "tool": "batin v0.1.0",
  "findings": [
    {
      "path": "/evidence/malware.exe",
      "type": "exe",
      "threat": "Dangerous",
      "sha256": "def456...",
      "notes": "ملف تنفيذي مضغوط، إنتروبيا 7.85"
    }
  ]
}
```

---

:::tip للمحققين

1. **استخدم دائماً `--hash`** للحفاظ على سلامة الأدلة
2. **اعمل على نسخ** وليس الأصول
3. **وثق كل خطوة** بما فيها أوامر باطن المستخدمة
4. **احتفظ بالمخرجات الخام** (JSON) للمراجعة لاحقاً
5. **تحقق من النتائج** باستخدام أدوات متعددة

:::
