//! Archive Scanning Example
//!
//! Demonstrates how to scan archive files (ZIP, TAR, etc.) for threats.

use batin::{archive, DetectionConfig, FileType, ThreatLevel};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let archive_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sample.zip".to_string());

    println!("📦 Analyzing archive: {}\n", archive_path);

    // Progress channel available if needed for async progress tracking
    // Currently unused as we process synchronously in the example
    let _progress_channel = tokio::sync::mpsc::unbounded_channel::<batin::BatchProgress>();
    let config = DetectionConfig::default();
    let path = std::path::Path::new(&archive_path);

    // First, analyze the archive itself
    let archive_type = FileType::from_file_path(path, &config).await?;
    println!("Archive Format: {}", archive_type.extension);
    println!("MIME Type: {}", archive_type.mime_type);
    println!("Threat Level: {:?}", archive_type.threat_level);

    // Check for embedded threats in archive
    if !archive_type.embedded_threats.is_empty() {
        println!("\n⚠️  Embedded Threats Detected:");
        for threat in &archive_type.embedded_threats {
            println!(
                "  • {:?} at offset {} - {}",
                threat.threat_type, threat.offset, threat.description
            );
        }
    }

    // Scan archive contents
    println!("\n📂 Archive Contents Analysis:");

    let data = std::fs::read(&archive_path)?;
    match archive::scan_archive(&data, 3, &config) {
        Ok(entries) => {
            // Check for zip bomb
            if archive::detect_zip_bomb(&entries) {
                println!("🚨 WARNING: Potential ZIP bomb detected!");
            }

            for entry in entries {
                let threat_icon = match entry.file_type.as_ref().map(|ft| &ft.threat_level) {
                    Some(ThreatLevel::Safe) => "✅",
                    Some(ThreatLevel::Suspicious) => "⚠️",
                    Some(ThreatLevel::Dangerous) => "🔴",
                    Some(ThreatLevel::Critical) => "💀",
                    None => "❓",
                };

                let file_ext = entry
                    .file_type
                    .as_ref()
                    .map(|ft| ft.extension.clone())
                    .unwrap_or_else(|| "unknown".to_string());

                println!(
                    "  {} {} ({} bytes) - {}",
                    threat_icon, entry.path, entry.size, file_ext
                );
            }
        }
        Err(e) => {
            println!("  Could not analyze contents: {}", e);
        }
    }

    Ok(())
}
