---
sidebar_position: 7
title: وحدة الدفعات
description: تعمق في تنفيذ معالجة الملفات المتوازية
---

# تعمق في وحدة الدفعات

تحليل شامل لوحدة `src/io/batch.rs`.

## الغرض

وحدة الدفعات توفر **معالجة ملفات متوازية** لفحص المجلدات بكفاءة.

## المعالج

```rust
pub struct BatchProcessor {
    config: DetectionConfig,
}

impl BatchProcessor {
    pub async fn process_directory(
        &self,
        path: &str,
        progress: Option<mpsc::UnboundedSender<BatchProgress>>,
    ) -> Result<Vec<(PathBuf, Result<FileType>)>>
}
```

## تتبع التقدم

```rust
pub struct BatchProgress {
    pub total: usize,        // إجمالي الملفات
    pub processed: usize,    // الملفات المعالجة
    pub current_file: PathBuf, // الملف الحالي
}
```

## الميزات

- **I/O غير متزامن**: عمليات ملفات غير محجوبة مع Tokio
- **معالجة متوازية**: استخدام أنوية متعددة مع Rayon
- **تتبع التقدم**: تحديثات في الوقت الحقيقي
- **معالجة الأخطاء**: يستمر عند الأخطاء، يجمع النتائج

---

:::tip نصيحة أداء
للمجلدات الكبيرة:

- استخدم تتبع التقدم لعرض واجهة المستخدم
- ضبط `max_read_bytes` لتوازن السرعة/الدقة
- تمرير أنماط الاستبعاد لتخطي الملفات غير المطلوبة
:::
