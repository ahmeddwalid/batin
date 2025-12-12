//! PE Analysis Example
//!
//! Demonstrates how to analyze PE (Windows Executable) files.

use batin::analysis::pe_parser;
use batin::{DetectionConfig, FileType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sample.exe".to_string());

    println!("🔬 Analyzing PE file: {}\n", exe_path);

    let config = DetectionConfig::default();
    let path = std::path::Path::new(&exe_path);

    // Basic file type detection
    let file_type = FileType::from_file_path(path, &config).await?;

    println!("📋 Basic Information:");
    println!("  Format: {}", file_type.extension);
    println!("  MIME: {}", file_type.mime_type);
    println!("  Confidence: {:.1}%", file_type.confidence * 100.0);
    println!("  Threat Level: {:?}", file_type.threat_level);

    // Entropy analysis
    if let Some(entropy) = &file_type.entropy_profile {
        println!("\n📊 Entropy Analysis:");
        println!("  Global Entropy: {:.2} bits/byte", entropy.global_entropy);
        println!(
            "  Is Packed: {}",
            if entropy.is_packed {
                "⚠️ YES"
            } else {
                "No"
            }
        );
        println!(
            "  Is Encrypted: {}",
            if entropy.is_encrypted {
                "⚠️ YES"
            } else {
                "No"
            }
        );
    }

    // PE-specific analysis using parse_binary
    let data = std::fs::read(&exe_path)?;
    match pe_parser::parse_binary(&data) {
        Ok(pe_info) => {
            println!("\n🔧 Binary Details:");
            println!("  Format: {:?}", pe_info.format);
            println!("  Architecture: {}", pe_info.architecture);
            if let Some(entry) = pe_info.entry_point {
                println!("  Entry Point: 0x{:X}", entry);
            }

            if !pe_info.sections.is_empty() {
                println!("\n📑 Sections ({} total):", pe_info.sections.len());
                for section in pe_info.sections.iter().take(5) {
                    println!(
                        "    • {} (vsize: {}, raw: {})",
                        section.name, section.virtual_size, section.raw_size
                    );
                }
            }

            if !pe_info.imports.is_empty() {
                println!("\n📥 Imports ({} total):", pe_info.imports.len());
                for import in pe_info.imports.iter().take(10) {
                    println!("    • {}", import);
                }
                if pe_info.imports.len() > 10 {
                    println!("    ... and {} more", pe_info.imports.len() - 10);
                }
            }

            if !pe_info.exports.is_empty() {
                println!("\n📤 Exports ({} total):", pe_info.exports.len());
                for export in pe_info.exports.iter().take(10) {
                    println!("    • {}", export);
                }
                if pe_info.exports.len() > 10 {
                    println!("    ... and {} more", pe_info.exports.len() - 10);
                }
            }

            // Suspicious API detection
            let suspicious_apis = [
                "VirtualAlloc",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "LoadLibrary",
                "GetProcAddress",
                "NtCreateThread",
            ];

            let found_suspicious: Vec<_> = pe_info
                .imports
                .iter()
                .filter(|i| suspicious_apis.iter().any(|s| i.contains(s)))
                .collect();

            if !found_suspicious.is_empty() {
                println!("\n🚨 Suspicious APIs Detected:");
                for api in found_suspicious {
                    println!("    ⚠️ {}", api);
                }
            }
        }
        Err(e) => {
            println!("\n❌ Failed to parse binary structure: {}", e);
        }
    }

    Ok(())
}
