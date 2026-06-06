---
sidebar_position: 2
title: التثبيت
description: تثبيت باطن على Linux أو Windows أو macOS أو FreeBSD
---

# التثبيت

يمكن تثبيت باطن من خلال مديري الحزم المختلفة أو بناؤه من المصدر.

## المتطلبات

- **Rust 1.75+** (إذا كنت تبني من المصدر)
- **Node.js 18+** (إذا كنت تبني التوثيق)

## مديرو الحزم

### 🍎 macOS (Homebrew)

```bash
brew tap ahmeddwalid/batin
brew install batin
```

### 🐧 Arch Linux (AUR)

باستخدام `yay`:

```bash
yay -S batin
```

### 🎩 Fedora / RHEL (COPR)

```bash
sudo dnf copr enable ahmeddwalid/batin
sudo dnf install batin
```

### 🍥 Debian / Ubuntu

```bash
sudo add-apt-repository ppa:ahmeddwalid/batin
sudo apt update
sudo apt install batin
```

### 🪟 Windows (Chocolatey)

```powershell
choco install batin
```

## استخدام Cargo

إذا كان لديك Rust مثبت، يمكنك تثبيت باطن مباشرة من crates.io:

```bash
cargo install batin
```

### مع ميزات محددة

```bash
# تثبيت كامل (جميع الميزات)
cargo install batin --all-features

# تثبيت أدنى (الكشف الأساسي فقط)
cargo install batin --no-default-features

# مع ميزات محددة
cargo install batin --features "hashing,archive"
```

## البناء من المصدر

### 1. استنساخ المستودع

```bash
git clone https://github.com/ahmeddwalid/batin.git
cd batin
```

### 2. بناء الإصدار

```bash
cargo build --release
```

الملف الثنائي سيكون في `target/release/batin`.

### 3. التثبيت محلياً

```bash
# نسخ إلى مجلد في PATH
sudo cp target/release/batin /usr/local/bin/

# أو التثبيت عبر cargo
cargo install --path .
```

### 4. التحقق من التثبيت

```bash
batin --version
```

## Docker

### سحب من Docker Hub

```bash
docker pull ahmeddwalid/batin:latest
```

### تشغيل الحاوية

```bash
# فحص ملف واحد
docker run --rm -v /path/to/files:/data ahmeddwalid/batin scan /data/file.pdf

# فحص مجلد
docker run --rm -v /path/to/files:/data ahmeddwalid/batin scan /data --recursive
```

---

:::tip الخطوات التالية
الآن بعد تثبيت باطن، توجه إلى دليل [البداية السريعة](./quickstart) لإجراء أول فحص لك!
:::
