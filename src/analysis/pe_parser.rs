//! PE/ELF binary parsing module
//!
//! Extracts metadata from PE (Windows) and ELF (Linux/Unix) executables using goblin.

use crate::Result;
use goblin::{elf, pe, Object};

/// Binary format enumeration
#[derive(Debug, Clone, serde::Serialize)]
pub enum BinaryFormat {
    /// Windows Portable Executable
    PE,
    /// Unix/Linux Executable and Linkable Format
    ELF,
    /// macOS Mach-O
    MachO,
    /// Unknown binary format
    Unknown,
}

/// Section information
#[derive(Debug, Clone, serde::Serialize)]
pub struct Section {
    /// Section name
    pub name: String,
    /// Virtual size
    pub virtual_size: u64,
    /// Raw size on disk
    pub raw_size: u64,
    /// Section characteristics/flags
    pub characteristics: u32,
}

/// Binary metadata structure
#[derive(Debug, Clone, serde::Serialize)]
pub struct BinaryMetadata {
    /// Binary format type
    pub format: BinaryFormat,
    /// Target architecture
    pub architecture: String,
    /// List of imported functions/libraries
    pub imports: Vec<String>,
    /// List of exported functions
    pub exports: Vec<String>,
    /// Binary sections
    pub sections: Vec<Section>,
    /// Entry point address
    pub entry_point: Option<u64>,
}

/// Parse binary file and extract metadata
///
/// # Examples
/// ```no_run
/// use batin::analysis::pe_parser::parse_binary;
///
/// let exe_data = std::fs::read("program.exe").unwrap();
/// let metadata = parse_binary(&exe_data).unwrap();
/// println!("Architecture: {}", metadata.architecture);
/// println!("Imports: {:?}", metadata.imports);
/// ```
pub fn parse_binary(data: &[u8]) -> Result<BinaryMetadata> {
    let obj = Object::parse(data).map_err(|e| {
        crate::DetectionError::CorruptedStructure(format!("Failed to parse binary: {}", e))
    })?;

    match obj {
        Object::PE(pe) => parse_pe(pe),
        Object::Elf(elf) => parse_elf(elf),
        Object::Mach(_mach) => parse_mach(),
        _ => Ok(BinaryMetadata {
            format: BinaryFormat::Unknown,
            architecture: "unknown".to_string(),
            imports: Vec::new(),
            exports: Vec::new(),
            sections: Vec::new(),
            entry_point: None,
        }),
    }
}

fn parse_pe(pe: pe::PE) -> Result<BinaryMetadata> {
    let architecture = match pe.header.coff_header.machine {
        0x14c => "i386",
        0x8664 => "x86_64",
        0x1c0 => "arm",
        0xaa64 => "arm64",
        _ => "unknown",
    }
    .to_string();

    // Extract imports from the import table
    // Each import has dll (library name) and name (function name as Cow<str>)
    let imports: Vec<String> = pe
        .imports
        .iter()
        .map(|import| format!("{}::{}", import.dll, import.name))
        .collect();

    // Extract exports from the export table
    let exports: Vec<String> = pe
        .exports
        .iter()
        .filter_map(|export| export.name.map(|n| n.to_string()))
        .collect();

    // Extract sections
    let sections = pe
        .sections
        .iter()
        .map(|section| Section {
            name: String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string(),
            virtual_size: section.virtual_size as u64,
            raw_size: section.size_of_raw_data as u64,
            characteristics: section.characteristics,
        })
        .collect();

    let entry_point = Some(pe.entry as u64);

    Ok(BinaryMetadata {
        format: BinaryFormat::PE,
        architecture,
        imports,
        exports,
        sections,
        entry_point,
    })
}

fn parse_elf(elf: elf::Elf) -> Result<BinaryMetadata> {
    let architecture = match elf.header.e_machine {
        3 => "i386",
        62 => "x86_64",
        40 => "arm",
        183 => "arm64",
        243 => "riscv",
        _ => "unknown",
    }
    .to_string();

    // Extract imports (dynamic symbols)
    let mut imports = Vec::new();
    for dynsym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
            if dynsym.is_import() {
                imports.push(name.to_string());
            }
        }
    }

    // Extract exports
    let mut exports = Vec::new();
    for dynsym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
            if dynsym.is_function() && !dynsym.is_import() {
                exports.push(name.to_string());
            }
        }
    }

    // Extract sections
    let sections = elf
        .section_headers
        .iter()
        .filter_map(|section| {
            elf.shdr_strtab.get_at(section.sh_name).map(|name| Section {
                name: name.to_string(),
                virtual_size: section.sh_size,
                raw_size: section.sh_size,
                // ELF sh_flags is u64, but common flags fit in lower 32 bits
                characteristics: (section.sh_flags & 0xFFFF_FFFF) as u32,
            })
        })
        .collect();

    let entry_point = Some(elf.entry);

    Ok(BinaryMetadata {
        format: BinaryFormat::ELF,
        architecture,
        imports,
        exports,
        sections,
        entry_point,
    })
}

fn parse_mach() -> Result<BinaryMetadata> {
    // Basic Mach-O support
    Ok(BinaryMetadata {
        format: BinaryFormat::MachO,
        architecture: "unknown".to_string(),
        imports: Vec::new(),
        exports: Vec::new(),
        sections: Vec::new(),
        entry_point: None,
    })
}
