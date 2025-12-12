//! CLI Scanner module
//!
//! Handles recursive directory scanning and file processing with enhanced UI.

use super::console::{self, theme};
use batin::file_io::hasher;
use batin::{DetectionConfig, FileType, ThreatLevel};
use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, ContentArrangement, Table,
};
use glob::Pattern;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

/// Scan options
#[derive(Clone)]
pub struct ScanOptions {
    pub recursive: bool,
    pub json: bool,
    pub csv: bool,
    pub verbose: bool,
    pub output: Option<PathBuf>,
    pub exclude: Vec<String>,
    pub min_threat: Option<ThreatLevel>,
    pub include_hash: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            recursive: false,
            json: false,
            csv: false,
            verbose: false,
            output: None,
            exclude: Vec::new(),
            min_threat: None,
            include_hash: false,
        }
    }
}

/// Run scanner
pub async fn run_scan(path: PathBuf, options: ScanOptions) -> anyhow::Result<()> {
    let config = DetectionConfig::default();
    let mut results = Vec::new();
    let start_time = Instant::now();

    // Print banner for interactive output (not JSON/CSV)
    if !options.json && !options.csv {
        console::print_banner();
        println!(
            "  {} Scanning: {}\n",
            "🔍".bold(),
            path.display().to_string().cyan()
        );
    }

    // Compile exclude patterns
    let exclude_patterns: Vec<Pattern> = options
        .exclude
        .iter()
        .filter_map(|p| Pattern::new(p).ok())
        .collect();

    if path.is_file() {
        if !is_excluded(&path, &exclude_patterns) {
            process_file(&path, &config, &options, &mut results).await?;
        }
    } else if path.is_dir() {
        // Limit max depth to 100 to prevent DoS from malicious symlink structures
        const MAX_RECURSIVE_DEPTH: usize = 100;
        let walker = WalkDir::new(&path).max_depth(if options.recursive {
            MAX_RECURSIVE_DEPTH
        } else {
            1
        });

        let entries: Vec<_> = walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| !is_excluded(e.path(), &exclude_patterns))
            .collect();

        // Create enhanced progress bar
        let pb = ProgressBar::new(entries.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.cyan} {msg}\n  [{elapsed_precise}] ▕{bar:40.cyan/blue}▏ {pos}/{len} ({percent}%) • ETA: {eta}",
                )
                .unwrap()
                .progress_chars("█▓▒░ "),
        );
        pb.set_message("Analyzing files...");

        for entry in entries {
            let filename = entry
                .path()
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            pb.set_message(format!("Scanning: {}", filename));
            process_file(entry.path(), &config, &options, &mut results).await?;
            pb.inc(1);
        }
        pb.finish_and_clear();

        if !options.json && !options.csv {
            console::print_success("Scan complete!");
        }
    }

    let duration = start_time.elapsed();

    // Filter by minimum threat level if specified
    let filtered_results: Vec<_> = if let Some(min_level) = options.min_threat {
        results
            .into_iter()
            .filter(|r| {
                threat_level_value(&r.file_type.threat_level) >= threat_level_value(&min_level)
            })
            .collect()
    } else {
        results
    };

    // Output results
    output_results(&filtered_results, &options, duration)?;

    Ok(())
}

fn is_excluded(path: &Path, patterns: &[Pattern]) -> bool {
    let path_str = path.to_string_lossy();
    patterns.iter().any(|p| p.matches(&path_str))
}

fn threat_level_value(level: &ThreatLevel) -> u8 {
    match level {
        ThreatLevel::Safe => 0,
        ThreatLevel::Suspicious => 1,
        ThreatLevel::Dangerous => 2,
        ThreatLevel::Critical => 3,
    }
}

async fn process_file(
    path: &Path,
    config: &DetectionConfig,
    options: &ScanOptions,
    results: &mut Vec<ScanResult>,
) -> anyhow::Result<()> {
    match FileType::from_file_path(path, config).await {
        Ok(mut file_type) => {
            // Calculate hashes if requested (using async I/O)
            if options.include_hash {
                if let Ok(data) = tokio::fs::read(path).await {
                    file_type.hashes = Some(hasher::calculate_hashes(&data, false));
                }
            }

            if options.verbose {
                println!("Processed: {}", path.display());
            }
            results.push(ScanResult {
                path: path.to_string_lossy().to_string(),
                file_type,
            });
        }
        Err(e) => {
            // Show unrecognized files in output with unknown type
            if options.verbose {
                eprintln!("Error processing {}: {}", path.display(), e);
            }
            // Create an unknown file type entry so the file appears in results
            let unknown_type = FileType {
                extension: "unknown".to_string(),
                mime_type: "application/octet-stream".to_string(),
                confidence: 0.0,
                threat_level: ThreatLevel::Safe,
                detected_formats: vec![],
                entropy_profile: None,
                embedded_threats: vec![],
                hashes: None,
                binary_metadata: None,
            };
            results.push(ScanResult {
                path: path.to_string_lossy().to_string(),
                file_type: unknown_type,
            });
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct ScanResult {
    path: String,
    file_type: FileType,
}

fn output_results(
    results: &[ScanResult],
    options: &ScanOptions,
    duration: std::time::Duration,
) -> anyhow::Result<()> {
    if options.json {
        let json = serde_json::to_string_pretty(&results)?;
        write_output(&json, &options.output)?;
    } else if options.csv {
        let csv_output = generate_csv(results)?;
        write_output(&csv_output, &options.output)?;
    } else {
        print_table(results);
        print_summary(results, duration);
    }
    Ok(())
}

fn write_output(content: &str, output_path: &Option<PathBuf>) -> anyhow::Result<()> {
    if let Some(path) = output_path {
        std::fs::write(path, content)?;
    } else {
        println!("{}", content);
    }
    Ok(())
}

fn generate_csv(results: &[ScanResult]) -> anyhow::Result<String> {
    let mut wtr = csv::Writer::from_writer(Vec::new());

    // Write header
    wtr.write_record(&[
        "Path",
        "Type",
        "MIME",
        "Confidence",
        "Threat Level",
        "Entropy",
        "Is Packed",
        "Is Encrypted",
        "Polyglot",
        "Embedded Threats",
        "MD5",
        "SHA256",
    ])?;

    for res in results {
        let entropy = res
            .file_type
            .entropy_profile
            .as_ref()
            .map(|e| format!("{:.2}", e.global_entropy))
            .unwrap_or_default();

        let is_packed = res
            .file_type
            .entropy_profile
            .as_ref()
            .map(|e| e.is_packed.to_string())
            .unwrap_or_default();

        let is_encrypted = res
            .file_type
            .entropy_profile
            .as_ref()
            .map(|e| e.is_encrypted.to_string())
            .unwrap_or_default();

        let polyglot = if res.file_type.detected_formats.len() > 1 {
            res.file_type.detected_formats.join(";")
        } else {
            String::new()
        };

        let embedded = res
            .file_type
            .embedded_threats
            .iter()
            .map(|t| format!("{:?}", t.threat_type))
            .collect::<Vec<_>>()
            .join(";");

        let md5 = res
            .file_type
            .hashes
            .as_ref()
            .map(|h| h.md5.clone())
            .unwrap_or_default();

        let sha256 = res
            .file_type
            .hashes
            .as_ref()
            .map(|h| h.sha256.clone())
            .unwrap_or_default();

        wtr.write_record(&[
            &res.path,
            &res.file_type.extension,
            &res.file_type.mime_type,
            &format!("{:.1}%", res.file_type.confidence * 100.0),
            &format!("{:?}", res.file_type.threat_level),
            &entropy,
            &is_packed,
            &is_encrypted,
            &polyglot,
            &embedded,
            &md5,
            &sha256,
        ])?;
    }

    wtr.flush()?;
    Ok(String::from_utf8(wtr.into_inner()?)?)
}

fn print_table(results: &[ScanResult]) {
    if results.is_empty() {
        println!("\n{}", "  No files found matching criteria.".dimmed());
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("File").fg(comfy_table::Color::Cyan),
            Cell::new("Type").fg(comfy_table::Color::Cyan),
            Cell::new("Confidence").fg(comfy_table::Color::Cyan),
            Cell::new("Threat").fg(comfy_table::Color::Cyan),
            Cell::new("Details").fg(comfy_table::Color::Cyan),
        ]);

    for res in results {
        let threat_color = match res.file_type.threat_level {
            ThreatLevel::Safe => comfy_table::Color::Green,
            ThreatLevel::Suspicious => comfy_table::Color::Yellow,
            ThreatLevel::Dangerous => comfy_table::Color::Red,
            ThreatLevel::Critical => comfy_table::Color::Red,
        };

        let threat_icon = console::threat_icon(&res.file_type.threat_level);
        let threat_str = format!("{} {:?}", threat_icon, res.file_type.threat_level);

        let mut details = Vec::new();
        if let Some(entropy) = &res.file_type.entropy_profile {
            if entropy.is_packed {
                details.push("📦 Packed");
            }
            if entropy.is_encrypted {
                details.push("🔐 Encrypted");
            }
        }
        if !res.file_type.embedded_threats.is_empty() {
            details.push("⚠ Embedded");
        }
        if res.file_type.detected_formats.len() > 1 {
            details.push("🔀 Polyglot");
        }
        if res.file_type.hashes.is_some() {
            details.push("# Hashed");
        }

        let details_str = if details.is_empty() {
            "─".to_string()
        } else {
            details.join(" ")
        };

        // Truncate long paths for display
        let display_path = if res.path.len() > 45 {
            format!("...{}", &res.path[res.path.len() - 42..])
        } else {
            res.path.clone()
        };

        // Apply row coloring based on threat level
        let row_color = match res.file_type.threat_level {
            ThreatLevel::Safe => None,
            ThreatLevel::Suspicious => Some(comfy_table::Color::Yellow),
            ThreatLevel::Dangerous => Some(comfy_table::Color::Red),
            ThreatLevel::Critical => Some(comfy_table::Color::Red),
        };

        let mut row = vec![
            Cell::new(&display_path),
            Cell::new(&res.file_type.extension),
            Cell::new(format!("{:.0}%", res.file_type.confidence * 100.0)),
            Cell::new(&threat_str).fg(threat_color),
            Cell::new(&details_str),
        ];

        // Color non-safe rows
        if let Some(color) = row_color {
            row[0] = row[0].clone().fg(color);
        }

        table.add_row(row);
    }

    println!("\n{}\n", table);
}

fn print_summary(results: &[ScanResult], duration: std::time::Duration) {
    let total = results.len();
    let safe = results
        .iter()
        .filter(|r| r.file_type.threat_level == ThreatLevel::Safe)
        .count();
    let suspicious = results
        .iter()
        .filter(|r| r.file_type.threat_level == ThreatLevel::Suspicious)
        .count();
    let dangerous = results
        .iter()
        .filter(|r| r.file_type.threat_level == ThreatLevel::Dangerous)
        .count();
    let critical = results
        .iter()
        .filter(|r| r.file_type.threat_level == ThreatLevel::Critical)
        .count();

    console::print_section("Scan Summary");

    // Threat distribution bars
    println!();
    console::print_threat_bar("Safe", safe, total, theme::SUCCESS);
    console::print_threat_bar("Suspicious", suspicious, total, theme::WARNING);
    console::print_threat_bar("Dangerous", dangerous, total, theme::DANGER);
    console::print_threat_bar("Critical", critical, total, theme::DANGER);
    println!();

    // Statistics
    console::print_separator();
    console::print_stats(total, duration);

    // Recommendations
    if critical > 0 {
        println!();
        console::print_error(&format!(
            "ALERT: {} critical threat(s) detected! Immediate review required.",
            critical
        ));
    } else if dangerous > 0 {
        println!();
        console::print_warning(&format!(
            "{} dangerous file(s) detected. Review recommended.",
            dangerous
        ));
    } else if suspicious > 0 {
        println!();
        console::print_info(&format!(
            "{} suspicious file(s) found. Consider investigating.",
            suspicious
        ));
    } else if total > 0 {
        println!();
        console::print_success("All files appear safe. No threats detected.");
    }

    println!();
}
