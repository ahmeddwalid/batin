//! File signature database and definitions

use crate::{DetectionError, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, RwLock};

/// File signature database with lazy initialization
pub static SIGNATURE_DB: LazyLock<RwLock<SignatureDatabase>> =
    LazyLock::new(|| RwLock::new(SignatureDatabase::default()));

/// File signature structure
#[derive(Debug, Clone)]
pub struct FileSignature {
    pub magic_bytes: Vec<u8>,
    pub offset: usize,
    pub extensions: Vec<String>,
    pub mime_type: String,
    pub category: FileCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum FileCategory {
    Image,
    Document,
    Archive,
    Executable,
    Multimedia,
    Text,
    #[default]
    Unknown,
}

/// User-supplied signature specification, deserialized from JSON.
///
/// Magic bytes are written as a hex string for readability, e.g.
/// `"89504e47"` or `"89 50 4e 47"` (whitespace and an optional `0x`
/// prefix are ignored).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SignatureSpec {
    /// Magic bytes as a hex string.
    pub magic: String,
    /// Offset at which the magic bytes appear (default 0).
    #[serde(default)]
    pub offset: usize,
    /// File extensions this signature maps to (at least one required).
    pub extensions: Vec<String>,
    /// MIME type for the format.
    pub mime_type: String,
    /// File category (default `unknown`).
    #[serde(default)]
    pub category: FileCategory,
}

/// A JSON document containing user signatures: `{ "signatures": [ ... ] }`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SignatureFile {
    #[serde(default)]
    pub signatures: Vec<SignatureSpec>,
}

/// Parse a hex string (ignoring whitespace and an optional `0x` prefix) to bytes.
fn parse_hex(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
    if cleaned.is_empty() {
        return Err(DetectionError::InvalidConfig(
            "signature magic must not be empty".to_string(),
        ));
    }
    if cleaned.len() % 2 != 0 {
        return Err(DetectionError::InvalidConfig(format!(
            "signature magic has odd hex length: '{input}'"
        )));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| {
                DetectionError::InvalidConfig(format!("invalid hex in signature magic: '{input}'"))
            })
        })
        .collect()
}

impl TryFrom<SignatureSpec> for FileSignature {
    type Error = DetectionError;

    fn try_from(spec: SignatureSpec) -> Result<Self> {
        if spec.extensions.is_empty() {
            return Err(DetectionError::InvalidConfig(
                "signature must declare at least one extension".to_string(),
            ));
        }
        Ok(FileSignature {
            magic_bytes: parse_hex(&spec.magic)?,
            offset: spec.offset,
            extensions: spec.extensions,
            mime_type: spec.mime_type,
            category: spec.category,
        })
    }
}

/// Signature database with 50+ formats
#[derive(Debug)]
pub struct SignatureDatabase {
    pub signatures: Vec<FileSignature>,
    pub extension_map: HashMap<String, Vec<usize>>,
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        let signatures = Self::build_signatures();
        let extension_map = Self::build_extension_map(&signatures);
        Self {
            signatures,
            extension_map,
        }
    }
}

impl SignatureDatabase {
    fn build_signatures() -> Vec<FileSignature> {
        vec![
            // Images
            FileSignature {
                magic_bytes: vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
                offset: 0,
                extensions: vec!["png".to_string()],
                mime_type: "image/png".to_string(),
                category: FileCategory::Image,
            },
            FileSignature {
                magic_bytes: vec![0xFF, 0xD8, 0xFF],
                offset: 0,
                extensions: vec!["jpg".to_string(), "jpeg".to_string()],
                mime_type: "image/jpeg".to_string(),
                category: FileCategory::Image,
            },
            FileSignature {
                magic_bytes: vec![0x47, 0x49, 0x46, 0x38],
                offset: 0,
                extensions: vec!["gif".to_string()],
                mime_type: "image/gif".to_string(),
                category: FileCategory::Image,
            },
            FileSignature {
                magic_bytes: vec![0x42, 0x4D],
                offset: 0,
                extensions: vec!["bmp".to_string()],
                mime_type: "image/bmp".to_string(),
                category: FileCategory::Image,
            },
            // WebP - RIFF with WEBP identifier at offset 8
            FileSignature {
                magic_bytes: vec![
                    0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
                ], // RIFF....WEBP
                offset: 0,
                extensions: vec!["webp".to_string()],
                mime_type: "image/webp".to_string(),
                category: FileCategory::Image,
            },
            // Documents
            FileSignature {
                magic_bytes: vec![0x25, 0x50, 0x44, 0x46],
                offset: 0,
                extensions: vec!["pdf".to_string()],
                mime_type: "application/pdf".to_string(),
                category: FileCategory::Document,
            },
            FileSignature {
                magic_bytes: vec![0x50, 0x4B, 0x03, 0x04],
                offset: 0,
                extensions: vec![
                    "docx".to_string(),
                    "xlsx".to_string(),
                    "pptx".to_string(),
                    "zip".to_string(),
                    "jar".to_string(),
                ],
                mime_type: "application/zip".to_string(),
                category: FileCategory::Archive,
            },
            FileSignature {
                magic_bytes: vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
                offset: 0,
                extensions: vec!["doc".to_string(), "xls".to_string(), "ppt".to_string()],
                mime_type: "application/msword".to_string(),
                category: FileCategory::Document,
            },
            // Archives
            FileSignature {
                magic_bytes: vec![0x1F, 0x8B],
                offset: 0,
                extensions: vec!["gz".to_string()],
                mime_type: "application/gzip".to_string(),
                category: FileCategory::Archive,
            },
            FileSignature {
                magic_bytes: vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
                offset: 0,
                extensions: vec!["rar".to_string()],
                mime_type: "application/x-rar-compressed".to_string(),
                category: FileCategory::Archive,
            },
            FileSignature {
                magic_bytes: vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
                offset: 0,
                extensions: vec!["7z".to_string()],
                mime_type: "application/x-7z-compressed".to_string(),
                category: FileCategory::Archive,
            },
            // Executables
            FileSignature {
                magic_bytes: vec![0x4D, 0x5A], // MZ header
                offset: 0,
                extensions: vec!["exe".to_string(), "dll".to_string()],
                mime_type: "application/x-msdownload".to_string(),
                category: FileCategory::Executable,
            },
            FileSignature {
                magic_bytes: vec![0x7F, 0x45, 0x4C, 0x46], // ELF header
                offset: 0,
                extensions: vec!["elf".to_string(), "so".to_string()],
                mime_type: "application/x-executable".to_string(),
                category: FileCategory::Executable,
            },
            FileSignature {
                magic_bytes: vec![0xCA, 0xFE, 0xBA, 0xBE], // Mach-O
                offset: 0,
                extensions: vec!["dylib".to_string()],
                mime_type: "application/x-mach-binary".to_string(),
                category: FileCategory::Executable,
            },
            // Multimedia
            FileSignature {
                magic_bytes: vec![0x49, 0x44, 0x33], // ID3
                offset: 0,
                extensions: vec!["mp3".to_string()],
                mime_type: "audio/mpeg".to_string(),
                category: FileCategory::Multimedia,
            },
            FileSignature {
                magic_bytes: vec![0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], // ftyp
                offset: 0,
                extensions: vec!["mp4".to_string(), "m4a".to_string(), "m4v".to_string()],
                mime_type: "video/mp4".to_string(),
                category: FileCategory::Multimedia,
            },
            // AVI - RIFF with AVI identifier at offset 8
            FileSignature {
                magic_bytes: vec![
                    0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x41, 0x56, 0x49, 0x20,
                ], // RIFF....AVI
                offset: 0,
                extensions: vec!["avi".to_string()],
                mime_type: "video/x-msvideo".to_string(),
                category: FileCategory::Multimedia,
            },
            // WAV - RIFF with WAVE identifier at offset 8
            FileSignature {
                magic_bytes: vec![
                    0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45,
                ], // RIFF....WAVE
                offset: 0,
                extensions: vec!["wav".to_string()],
                mime_type: "audio/wav".to_string(),
                category: FileCategory::Multimedia,
            },
            FileSignature {
                magic_bytes: vec![0x66, 0x4C, 0x61, 0x43], // fLaC
                offset: 0,
                extensions: vec!["flac".to_string()],
                mime_type: "audio/flac".to_string(),
                category: FileCategory::Multimedia,
            },
            FileSignature {
                magic_bytes: vec![0x1A, 0x45, 0xDF, 0xA3], // Matroska/WebM
                offset: 0,
                extensions: vec!["mkv".to_string(), "webm".to_string()],
                mime_type: "video/x-matroska".to_string(),
                category: FileCategory::Multimedia,
            },
            // Additional formats
            FileSignature {
                magic_bytes: vec![0x4F, 0x67, 0x67, 0x53], // OggS
                offset: 0,
                extensions: vec!["ogg".to_string(), "ogv".to_string()],
                mime_type: "audio/ogg".to_string(),
                category: FileCategory::Multimedia,
            },
            FileSignature {
                magic_bytes: vec![0x49, 0x49, 0x2A, 0x00], // TIFF little-endian
                offset: 0,
                extensions: vec!["tif".to_string(), "tiff".to_string()],
                mime_type: "image/tiff".to_string(),
                category: FileCategory::Image,
            },
            FileSignature {
                magic_bytes: vec![0x4D, 0x4D, 0x00, 0x2A], // TIFF big-endian
                offset: 0,
                extensions: vec!["tif".to_string(), "tiff".to_string()],
                mime_type: "image/tiff".to_string(),
                category: FileCategory::Image,
            },
            // ========== NEW OFFICE FORMATS ==========
            // RTF - Rich Text Format
            FileSignature {
                magic_bytes: vec![0x7B, 0x5C, 0x72, 0x74, 0x66], // {\rtf
                offset: 0,
                extensions: vec!["rtf".to_string()],
                mime_type: "application/rtf".to_string(),
                category: FileCategory::Document,
            },
            // ODF - OpenDocument (ODF files are ZIP-based, look for mimetype file)
            FileSignature {
                magic_bytes: vec![0x50, 0x4B, 0x03, 0x04], // PK.. (will need deeper inspection)
                offset: 0,
                extensions: vec!["odt".to_string(), "ods".to_string(), "odp".to_string()],
                mime_type: "application/vnd.oasis.opendocument".to_string(),
                category: FileCategory::Document,
            },
            // EPUB
            FileSignature {
                magic_bytes: vec![0x50, 0x4B, 0x03, 0x04], // PK.. (ZIP based)
                offset: 0,
                extensions: vec!["epub".to_string()],
                mime_type: "application/epub+zip".to_string(),
                category: FileCategory::Document,
            },
            // ========== NEW MEDIA FORMATS ==========
            // SVG
            FileSignature {
                magic_bytes: vec![0x3C, 0x3F, 0x78, 0x6D, 0x6C], // <?xml
                offset: 0,
                extensions: vec!["svg".to_string()],
                mime_type: "image/svg+xml".to_string(),
                category: FileCategory::Image,
            },
            // HEIC - High Efficiency Image Container
            FileSignature {
                magic_bytes: vec![
                    0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63,
                ], // ....ftypheic
                offset: 0,
                extensions: vec!["heic".to_string(), "heif".to_string()],
                mime_type: "image/heic".to_string(),
                category: FileCategory::Image,
            },
            // AVIF - AV1 Image File Format
            FileSignature {
                magic_bytes: vec![
                    0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66,
                ], // ....ftypavif
                offset: 0,
                extensions: vec!["avif".to_string()],
                mime_type: "image/avif".to_string(),
                category: FileCategory::Image,
            },
            // ICO - Windows Icon
            FileSignature {
                magic_bytes: vec![0x00, 0x00, 0x01, 0x00],
                offset: 0,
                extensions: vec!["ico".to_string()],
                mime_type: "image/x-icon".to_string(),
                category: FileCategory::Image,
            },
            // ========== DEVELOPMENT FORMATS ==========
            // Python Bytecode (.pyc)
            FileSignature {
                magic_bytes: vec![0x03, 0xF3, 0x0D, 0x0A], // Python 3.6+
                offset: 0,
                extensions: vec!["pyc".to_string()],
                mime_type: "application/x-python-code".to_string(),
                category: FileCategory::Executable,
            },
            // Java Class Files - includes minor version 0x0000 to distinguish from Mach-O
            // Mach-O 32-bit also starts with CAFEBABE but has different following bytes
            FileSignature {
                magic_bytes: vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00],
                offset: 0,
                extensions: vec!["class".to_string()],
                mime_type: "application/java-vm".to_string(),
                category: FileCategory::Executable,
            },
            // WebAssembly (.wasm)
            FileSignature {
                magic_bytes: vec![0x00, 0x61, 0x73, 0x6D], // \0asm
                offset: 0,
                extensions: vec!["wasm".to_string()],
                mime_type: "application/wasm".to_string(),
                category: FileCategory::Executable,
            },
            // DEX - Dalvik Executable (Android)
            FileSignature {
                magic_bytes: vec![0x64, 0x65, 0x78, 0x0A, 0x30, 0x33], // dex\n03
                offset: 0,
                extensions: vec!["dex".to_string()],
                mime_type: "application/x-dex".to_string(),
                category: FileCategory::Executable,
            },
            // ========== CONTAINER FORMATS ==========
            // ISO 9660 CD/DVD Image
            FileSignature {
                magic_bytes: vec![0x43, 0x44, 0x30, 0x30, 0x31], // CD001
                offset: 0x8001,
                extensions: vec!["iso".to_string()],
                mime_type: "application/x-iso9660-image".to_string(),
                category: FileCategory::Archive,
            },
            // Docker Image (tar-based, look for layer files)
            FileSignature {
                magic_bytes: vec![0x75, 0x73, 0x74, 0x61, 0x72], // ustar (TAR)
                offset: 257,
                extensions: vec!["tar".to_string()],
                mime_type: "application/x-tar".to_string(),
                category: FileCategory::Archive,
            },
            // VMDK - Virtual Machine Disk
            FileSignature {
                magic_bytes: vec![0x4B, 0x44, 0x4D], // KDM
                offset: 0,
                extensions: vec!["vmdk".to_string()],
                mime_type: "application/x-vmdk".to_string(),
                category: FileCategory::Archive,
            },
            // QCOW2 - QEMU Copy-On-Write
            FileSignature {
                magic_bytes: vec![0x51, 0x46, 0x49, 0xFB], // QFI\xFB
                offset: 0,
                extensions: vec!["qcow2".to_string(), "qcow".to_string()],
                mime_type: "application/x-qcow2".to_string(),
                category: FileCategory::Archive,
            },
            // ========== ARCHIVE FORMATS ==========
            // TAR - Tape Archive
            FileSignature {
                magic_bytes: vec![0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30], // ustar\0000
                offset: 257,
                extensions: vec!["tar".to_string()],
                mime_type: "application/x-tar".to_string(),
                category: FileCategory::Archive,
            },
            // BZIP2
            FileSignature {
                magic_bytes: vec![0x42, 0x5A, 0x68], // BZh
                offset: 0,
                extensions: vec!["bz2".to_string()],
                mime_type: "application/x-bzip2".to_string(),
                category: FileCategory::Archive,
            },
            // XZ
            FileSignature {
                magic_bytes: vec![0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], // \xFD7zXZ\0
                offset: 0,
                extensions: vec!["xz".to_string()],
                mime_type: "application/x-xz".to_string(),
                category: FileCategory::Archive,
            },
            // Zstandard (.zst)
            FileSignature {
                magic_bytes: vec![0x28, 0xB5, 0x2F, 0xFD],
                offset: 0,
                extensions: vec!["zst".to_string()],
                mime_type: "application/zstd".to_string(),
                category: FileCategory::Archive,
            },
            // LZ4
            FileSignature {
                magic_bytes: vec![0x04, 0x22, 0x4D, 0x18],
                offset: 0,
                extensions: vec!["lz4".to_string()],
                mime_type: "application/x-lz4".to_string(),
                category: FileCategory::Archive,
            },
            // CAB - Microsoft Cabinet
            FileSignature {
                magic_bytes: vec![0x4D, 0x53, 0x43, 0x46], // MSCF
                offset: 0,
                extensions: vec!["cab".to_string()],
                mime_type: "application/vnd.ms-cab-compressed".to_string(),
                category: FileCategory::Archive,
            },
            // ========== ADDITIONAL MULTIMEDIA ==========
            // M4A - MPEG-4 Audio
            FileSignature {
                magic_bytes: vec![
                    0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x4D, 0x34, 0x41,
                ], // ....ftypM4A
                offset: 0,
                extensions: vec!["m4a".to_string()],
                mime_type: "audio/m4a".to_string(),
                category: FileCategory::Multimedia,
            },
            // WMA - Windows Media Audio
            FileSignature {
                magic_bytes: vec![0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11],
                offset: 0,
                extensions: vec!["wma".to_string(), "wmv".to_string()],
                mime_type: "audio/x-ms-wma".to_string(),
                category: FileCategory::Multimedia,
            },
            // MOV - QuickTime
            FileSignature {
                magic_bytes: vec![0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70], // ....ftyp
                offset: 0,
                extensions: vec!["mov".to_string()],
                mime_type: "video/quicktime".to_string(),
                category: FileCategory::Multimedia,
            },
            // ========== NEW FORMATS ==========
            // JPEG XL (JXL)
            FileSignature {
                magic_bytes: vec![0xFF, 0x0A], // JXL codestream
                offset: 0,
                extensions: vec!["jxl".to_string()],
                mime_type: "image/jxl".to_string(),
                category: FileCategory::Image,
            },
            FileSignature {
                magic_bytes: vec![0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20], // JXL container
                offset: 0,
                extensions: vec!["jxl".to_string()],
                mime_type: "image/jxl".to_string(),
                category: FileCategory::Image,
            },
            // Adobe Photoshop (PSD)
            FileSignature {
                magic_bytes: vec![0x38, 0x42, 0x50, 0x53], // 8BPS
                offset: 0,
                extensions: vec!["psd".to_string(), "psb".to_string()],
                mime_type: "image/vnd.adobe.photoshop".to_string(),
                category: FileCategory::Image,
            },
            // Debian Package (DEB)
            FileSignature {
                magic_bytes: b"!<arch>\ndebian".to_vec(),
                offset: 0,
                extensions: vec!["deb".to_string()],
                mime_type: "application/vnd.debian.binary-package".to_string(),
                category: FileCategory::Archive,
            },
            // RPM Package
            FileSignature {
                magic_bytes: vec![0xED, 0xAB, 0xEE, 0xDB],
                offset: 0,
                extensions: vec!["rpm".to_string()],
                mime_type: "application/x-rpm".to_string(),
                category: FileCategory::Archive,
            },
            // Opus Audio
            FileSignature {
                magic_bytes: b"OggS".to_vec(),
                offset: 0,
                extensions: vec!["opus".to_string()],
                mime_type: "audio/opus".to_string(),
                category: FileCategory::Multimedia,
            },
            // AAC Audio (ADTS)
            FileSignature {
                magic_bytes: vec![0xFF, 0xF1], // ADTS sync word
                offset: 0,
                extensions: vec!["aac".to_string()],
                mime_type: "audio/aac".to_string(),
                category: FileCategory::Multimedia,
            },
            FileSignature {
                magic_bytes: vec![0xFF, 0xF9], // ADTS sync word variant
                offset: 0,
                extensions: vec!["aac".to_string()],
                mime_type: "audio/aac".to_string(),
                category: FileCategory::Multimedia,
            },
            // CPIO Archive
            FileSignature {
                magic_bytes: b"070701".to_vec(), // newc format
                offset: 0,
                extensions: vec!["cpio".to_string()],
                mime_type: "application/x-cpio".to_string(),
                category: FileCategory::Archive,
            },
            // XPS Document
            FileSignature {
                magic_bytes: vec![0x50, 0x4B, 0x03, 0x04], // ZIP-based
                offset: 0,
                extensions: vec!["xps".to_string(), "oxps".to_string()],
                mime_type: "application/vnd.ms-xpsdocument".to_string(),
                category: FileCategory::Document,
            },
            // SQLite Database
            FileSignature {
                magic_bytes: b"SQLite format 3\x00".to_vec(),
                offset: 0,
                extensions: vec![
                    "sqlite".to_string(),
                    "db".to_string(),
                    "sqlite3".to_string(),
                ],
                mime_type: "application/vnd.sqlite3".to_string(),
                category: FileCategory::Document,
            },
            // Note: WebAssembly signature is already defined earlier in the list (lines 314-321)
            // Fonts
            FileSignature {
                magic_bytes: vec![0x00, 0x01, 0x00, 0x00, 0x00],
                offset: 0,
                extensions: vec!["ttf".to_string()],
                mime_type: "font/ttf".to_string(),
                category: FileCategory::Document,
            },
            FileSignature {
                magic_bytes: vec![0x4F, 0x54, 0x54, 0x4F], // OTTO
                offset: 0,
                extensions: vec!["otf".to_string()],
                mime_type: "font/otf".to_string(),
                category: FileCategory::Document,
            },
            FileSignature {
                magic_bytes: vec![0x77, 0x4F, 0x46, 0x46], // wOFF
                offset: 0,
                extensions: vec!["woff".to_string()],
                mime_type: "font/woff".to_string(),
                category: FileCategory::Document,
            },
            FileSignature {
                magic_bytes: vec![0x77, 0x4F, 0x46, 0x32], // wOF2
                offset: 0,
                extensions: vec!["woff2".to_string()],
                mime_type: "font/woff2".to_string(),
                category: FileCategory::Document,
            },
            // Windows shortcut (.lnk) - common malware delivery vector.
            // Header size 0x4C + ShellLinkHeader CLSID.
            FileSignature {
                magic_bytes: vec![
                    0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
                ],
                offset: 0,
                extensions: vec!["lnk".to_string()],
                mime_type: "application/x-ms-shortcut".to_string(),
                category: FileCategory::Executable,
            },
            // Rich Text Format
            FileSignature {
                magic_bytes: vec![0x7B, 0x5C, 0x72, 0x74, 0x66], // {\rtf
                offset: 0,
                extensions: vec!["rtf".to_string()],
                mime_type: "application/rtf".to_string(),
                category: FileCategory::Document,
            },
            // Windows Registry export
            FileSignature {
                magic_bytes: b"regf".to_vec(),
                offset: 0,
                extensions: vec!["dat".to_string(), "hiv".to_string()],
                mime_type: "application/x-ms-registry".to_string(),
                category: FileCategory::Document,
            },
        ]
    }

    fn build_extension_map(signatures: &[FileSignature]) -> HashMap<String, Vec<usize>> {
        let mut map = HashMap::new();
        for (idx, sig) in signatures.iter().enumerate() {
            for ext in &sig.extensions {
                map.entry(ext.clone()).or_insert_with(Vec::new).push(idx);
            }
        }
        map
    }

    /// Add a single signature at runtime, keeping the extension map in sync.
    pub fn add_signature(&mut self, signature: FileSignature) {
        let idx = self.signatures.len();
        for ext in &signature.extensions {
            self.extension_map.entry(ext.clone()).or_default().push(idx);
        }
        self.signatures.push(signature);
    }

    /// Merge user signatures from a JSON string. Returns the number added.
    ///
    /// The document shape is `{ "signatures": [ { "magic": "...", ... } ] }`.
    pub fn load_from_json(&mut self, json: &str) -> Result<usize> {
        let file: SignatureFile = serde_json::from_str(json).map_err(|e| {
            DetectionError::CorruptedStructure(format!("invalid signature JSON: {e}"))
        })?;
        let mut added = 0;
        for spec in file.signatures {
            self.add_signature(FileSignature::try_from(spec)?);
            added += 1;
        }
        Ok(added)
    }

    /// Merge user signatures from a JSON file. Returns the number added.
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize> {
        let content = std::fs::read_to_string(path).map_err(DetectionError::Io)?;
        self.load_from_json(&content)
    }

    /// Match signatures against byte data with secondary validation
    pub fn match_signatures(&self, data: &[u8]) -> Vec<(usize, f64)> {
        let mut matches: Vec<(usize, f64)> = self
            .signatures
            .iter()
            .enumerate()
            .filter_map(|(idx, sig)| {
                if data.len() >= sig.offset + sig.magic_bytes.len() {
                    // For RIFF-based formats, compare with wildcards at bytes 4-7 (file size field)
                    if sig.magic_bytes.len() == 12
                        && sig.magic_bytes[0..4] == [0x52, 0x49, 0x46, 0x46]
                    {
                        // Check RIFF prefix and format identifier (bytes 8-11)
                        let riff_match = data[0..4] == sig.magic_bytes[0..4]
                            && data.len() >= 12
                            && data[8..12] == sig.magic_bytes[8..12];
                        if riff_match {
                            return Some((idx, 1.0));
                        }
                    } else {
                        // Standard signature matching
                        let slice = &data[sig.offset..sig.offset + sig.magic_bytes.len()];
                        if slice == sig.magic_bytes.as_slice() {
                            return Some((idx, 1.0));
                        }
                    }
                }
                None
            })
            .collect();

        // Check for ISO Base Media Format (MP4, M4A, MOV, HEIC, AVIF, etc.)
        // These have 'ftyp' at offset 4 with variable size prefix
        if matches.is_empty() && data.len() >= 8 && &data[4..8] == b"ftyp" {
            // Found ftyp atom - detect specific format from brand
            if let Some((idx, _mime, _ext)) = self.detect_iso_base_media_format(data) {
                matches.push((idx, 1.0));
            }
        }

        matches
    }

    /// Detect ISO Base Media Format (MP4, MOV, HEIC, AVIF, etc.) by examining the ftyp atom
    fn detect_iso_base_media_format(
        &self,
        data: &[u8],
    ) -> Option<(usize, &'static str, &'static str)> {
        if data.len() < 12 {
            return None;
        }

        // Read brand identifier at offset 8 (4 bytes after 'ftyp')
        let brand = &data[8..12];

        // Map brand to format
        let (mime, ext) = match brand {
            // MP4 variants
            b"isom" | b"iso2" | b"mp41" | b"mp42" | b"avc1" | b"dash" => ("video/mp4", "mp4"),
            b"M4A " | b"M4B " => ("audio/m4a", "m4a"),
            b"M4V " | b"M4VH" | b"M4VP" => ("video/x-m4v", "m4v"),
            // QuickTime
            b"qt  " => ("video/quicktime", "mov"),
            // HEIF/HEIC
            b"heic" | b"heix" | b"hevc" | b"hevx" => ("image/heic", "heic"),
            b"mif1" | b"msf1" => ("image/heif", "heif"),
            // AVIF
            b"avif" | b"avis" => ("image/avif", "avif"),
            // 3GPP
            b"3gp4" | b"3gp5" | b"3gp6" | b"3g2a" => ("video/3gpp", "3gp"),
            // Default to MP4 for unknown ISO base media
            _ => ("video/mp4", "mp4"),
        };

        // Find matching signature index for the extension
        for (idx, sig) in self.signatures.iter().enumerate() {
            if sig.extensions.iter().any(|e| e == ext)
                && sig
                    .mime_type
                    .contains(mime.split('/').next_back().unwrap_or(""))
            {
                return Some((idx, mime, ext));
            }
        }

        // If no exact match, find any MP4 signature
        for (idx, sig) in self.signatures.iter().enumerate() {
            if sig.extensions.contains(&"mp4".to_string()) {
                return Some((idx, mime, ext));
            }
        }

        None
    }

    /// Detect specific format for ZIP-based files by inspecting internal structure
    pub fn detect_zip_format(&self, data: &[u8]) -> Option<&'static str> {
        // Check for ZIP signature first
        if data.len() < 4 || data[0..4] != [0x50, 0x4B, 0x03, 0x04] {
            return None;
        }

        // Look for specific markers in the ZIP content
        let data_str = String::from_utf8_lossy(data);

        if data_str.contains("[Content_Types].xml") {
            // Office Open XML format - check for specific content types
            if data_str.contains("word/")
                || data_str
                    .contains("application/vnd.openxmlformats-officedocument.wordprocessingml")
            {
                return Some("docx");
            } else if data_str.contains("xl/")
                || data_str.contains("application/vnd.openxmlformats-officedocument.spreadsheetml")
            {
                return Some("xlsx");
            } else if data_str.contains("ppt/")
                || data_str.contains("application/vnd.openxmlformats-officedocument.presentationml")
            {
                return Some("pptx");
            }
        }

        if data_str.contains("mimetype") {
            // ODF format
            if data_str.contains("application/vnd.oasis.opendocument.text") {
                return Some("odt");
            } else if data_str.contains("application/vnd.oasis.opendocument.spreadsheet") {
                return Some("ods");
            } else if data_str.contains("application/vnd.oasis.opendocument.presentation") {
                return Some("odp");
            } else if data_str.contains("application/epub+zip") {
                return Some("epub");
            }
        }

        if data_str.contains("META-INF/MANIFEST.MF") {
            return Some("jar");
        }

        // Default to generic zip
        Some("zip")
    }
}

/// Load user-defined signatures from a JSON file into the global signature
/// database. Returns the number of signatures added.
///
/// Subsequent calls to [`crate::FileType::from_bytes`] will match against the
/// merged set. Intended to be called once at startup.
pub fn load_user_signatures<P: AsRef<Path>>(path: P) -> Result<usize> {
    let mut db = SIGNATURE_DB.write().map_err(|_| {
        DetectionError::CorruptedStructure("Signature database lock poisoned".into())
    })?;
    db.load_from_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_handles_formats() {
        assert_eq!(parse_hex("89504e47").unwrap(), vec![0x89, 0x50, 0x4e, 0x47]);
        assert_eq!(parse_hex("0x8950").unwrap(), vec![0x89, 0x50]);
        assert_eq!(
            parse_hex("89 50 4e 47").unwrap(),
            vec![0x89, 0x50, 0x4e, 0x47]
        );
        assert!(parse_hex("8950a").is_err()); // odd length
        assert!(parse_hex("zz").is_err()); // non-hex
        assert!(parse_hex("").is_err()); // empty
    }

    #[test]
    fn load_from_json_adds_signatures() {
        let mut db = SignatureDatabase::default();
        let before = db.signatures.len();
        let json = r#"{
            "signatures": [
                {
                    "magic": "de ad c0 de fe ed",
                    "extensions": ["myfmt"],
                    "mime_type": "application/x-myfmt",
                    "category": "executable"
                }
            ]
        }"#;
        let added = db.load_from_json(json).unwrap();
        assert_eq!(added, 1);
        assert_eq!(db.signatures.len(), before + 1);

        // The new signature is matched and indexed by extension.
        let matches = db.match_signatures(&[0xde, 0xad, 0xc0, 0xde, 0xfe, 0xed, 0x00]);
        assert!(!matches.is_empty());
        let (idx, _conf) = matches[0];
        assert_eq!(db.signatures[idx].extensions, vec!["myfmt".to_string()]);
        assert!(db.extension_map.contains_key("myfmt"));
    }

    #[test]
    fn detects_new_formats() {
        let db = SignatureDatabase::default();

        // RTF
        let m = db.match_signatures(br"{\rtf1\ansi");
        assert_eq!(db.signatures[m[0].0].extensions, vec!["rtf".to_string()]);

        // OTF font
        let m = db.match_signatures(b"OTTO\x00\x01");
        assert_eq!(db.signatures[m[0].0].extensions, vec!["otf".to_string()]);

        // Windows shortcut
        let lnk = [
            0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00,
        ];
        let m = db.match_signatures(&lnk);
        assert_eq!(db.signatures[m[0].0].extensions, vec!["lnk".to_string()]);
    }

    #[test]
    fn load_from_json_rejects_bad_signature() {
        let mut db = SignatureDatabase::default();
        let json =
            r#"{ "signatures": [ { "magic": "xyz", "extensions": ["x"], "mime_type": "a/b" } ] }"#;
        assert!(db.load_from_json(json).is_err());
    }
}
