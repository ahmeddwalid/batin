//! CLI Watcher module
//!
//! Watches a directory for new files and analyzes them in real-time with enhanced visual output.

use super::console::{self, theme};
use batin::{DetectionConfig, FileType, ThreatLevel};
use chrono::Local;
use colored::Colorize;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

/// Debounce duration - ignore duplicate events for the same file within this window
const DEBOUNCE_DURATION: Duration = Duration::from_millis(200);

/// Time to wait for file to stabilize after creation (file copy completion)
const FILE_STABILIZATION_DELAY: Duration = Duration::from_millis(50);

/// Run the file watcher with enhanced UI
pub async fn run_watch(path: PathBuf, verbose: bool) -> anyhow::Result<()> {
    // Print banner
    console::print_banner();

    println!(
        "  {} {} {}",
        "👁".bold(),
        "Watching:".bright_white(),
        path.display().to_string().cyan().bold()
    );
    println!(
        "  {} {}\n",
        "⏳".dimmed(),
        "Monitoring for new and modified files...".dimmed()
    );
    console::print_separator();
    println!("  {}", "Press Ctrl+C to stop watching.".color(theme::MUTED));
    console::print_separator();
    println!();

    let config = DetectionConfig::default();

    // Create a channel to receive file events
    let (tx, rx) = channel();

    // Create a watcher
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        Config::default().with_poll_interval(Duration::from_secs(1)),
    )?;

    // Start watching
    watcher.watch(&path, RecursiveMode::Recursive)?;

    // Debounce map: track when we last processed each file
    let mut last_processed: HashMap<PathBuf, Instant> = HashMap::new();

    // Process events
    loop {
        match rx.recv() {
            Ok(event) => {
                // Only process create and modify events
                if matches!(
                    event.kind,
                    notify::EventKind::Create(_) | notify::EventKind::Modify(_)
                ) {
                    // Collect all paths from this event first
                    let paths_to_process: Vec<PathBuf> = event.paths;

                    // Small delay to let files stabilize (especially for copies)
                    tokio::time::sleep(FILE_STABILIZATION_DELAY).await;

                    // Now process each file
                    for event_path in paths_to_process {
                        // Check if it's a file (after stabilization delay)
                        if !event_path.is_file() {
                            continue;
                        }

                        // Get fresh timestamp for debounce check
                        let now = Instant::now();

                        // Debounce: skip if we processed this file recently
                        if let Some(last_time) = last_processed.get(&event_path) {
                            if now.duration_since(*last_time) < DEBOUNCE_DURATION {
                                if verbose {
                                    let timestamp = Local::now().format("%H:%M:%S").to_string();
                                    println!(
                                        "  {} {} {} (skipped: duplicate event)",
                                        timestamp.color(theme::MUTED),
                                        "↻".color(theme::MUTED),
                                        event_path.display().to_string().dimmed()
                                    );
                                }
                                continue; // Skip duplicate event
                            }
                        }

                        // Record this processing time BEFORE processing
                        last_processed.insert(event_path.clone(), now);

                        // Clean up old entries periodically (avoid memory leak)
                        if last_processed.len() > 1000 {
                            let cleanup_now = Instant::now();
                            last_processed.retain(|_, time| {
                                cleanup_now.duration_since(*time) < Duration::from_secs(60)
                            });
                        }

                        process_new_file(&event_path, &config, verbose).await;
                    }
                }
            }
            Err(e) => {
                if verbose {
                    console::print_error(&format!("Watch error: {}", e));
                }
                break;
            }
        }
    }

    Ok(())
}

async fn process_new_file(path: &Path, config: &DetectionConfig, verbose: bool) {
    let timestamp = Local::now().format("%H:%M:%S").to_string();

    match FileType::from_file_path(path, config).await {
        Ok(file_type) => {
            // Use console helper functions instead of local match
            let icon = console::threat_icon(&file_type.threat_level);
            let color = console::threat_color(&file_type.threat_level);

            let filename = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());

            let threat_str = format!("{:?}", file_type.threat_level).to_lowercase();

            // Main line with timestamp
            println!(
                "  {} {} {} {} {}",
                timestamp.color(theme::MUTED),
                icon.color(color).bold(),
                filename.bold(),
                format!("[{}]", file_type.extension).color(theme::MUTED),
                threat_str.color(color)
            );

            // Show additional details for non-safe files
            if file_type.threat_level != ThreatLevel::Safe {
                let mut details = Vec::new();

                if let Some(entropy) = &file_type.entropy_profile {
                    if entropy.is_packed {
                        details.push(format!(
                            "📦 {}",
                            "Packed executable detected".color(theme::WARNING)
                        ));
                    }
                    if entropy.is_encrypted {
                        details.push(format!(
                            "🔐 {}",
                            "Encrypted content detected".color(theme::WARNING)
                        ));
                    }
                    details.push(format!(
                        "📊 Entropy: {:.2} bits/byte",
                        entropy.global_entropy
                    ));
                }

                if !file_type.embedded_threats.is_empty() {
                    details.push(format!(
                        "⚠ {} {}",
                        file_type.embedded_threats.len(),
                        "embedded threat(s) detected".color(theme::DANGER)
                    ));
                }

                if file_type.detected_formats.len() > 1 {
                    details.push(format!(
                        "🔀 Polyglot: {}",
                        file_type.detected_formats.join(", ").color(theme::DANGER)
                    ));
                }

                for detail in details {
                    println!("               └─ {}", detail);
                }
            }
        }
        Err(e) => {
            if verbose {
                println!(
                    "  {} {} {} {}",
                    timestamp.color(theme::MUTED),
                    "?".color(theme::MUTED),
                    path.display().to_string().dimmed(),
                    format!("- {}", e).color(theme::MUTED)
                );
            }
        }
    }
}
