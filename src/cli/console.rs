//! Console styling and UI utilities
//!
//! Provides themed output, banners, and visual indicators for the CLI.

use batin::ThreatLevel;
use colored::{Color, ColoredString, Colorize};

/// Theme colors for consistent styling across the CLI
pub mod theme {
    use colored::Color;

    pub const HEADER: Color = Color::Cyan;
    pub const SUCCESS: Color = Color::Green;
    pub const WARNING: Color = Color::Yellow;
    pub const DANGER: Color = Color::Red;
    pub const INFO: Color = Color::Blue;
    pub const MUTED: Color = Color::BrightBlack;
    pub const ACCENT: Color = Color::Magenta;
}

/// ASCII art banner for Batin
const BANNER: &str = r#"
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃  ▀█████████▄     ▄████████     ███      ▄█  ███▄▄▄▄       ┃
    ┃    ███    ███   ███    ███ ▀█████████▄ ███  ███▀▀▀██▄     ┃
    ┃    ███    ███   ███    ███    ▀███▀▀██ ███▌ ███   ███     ┃
    ┃   ▄███▄▄▄██▀    ███    ███     ███   ▀ ███▌ ███   ███     ┃
    ┃  ▀▀███▀▀▀██▄  ▀███████████     ███     ███▌ ███   ███     ┃
    ┃    ███    ██▄   ███    ███     ███     ███  ███   ███     ┃
    ┃    ███    ███   ███    ███     ███     ███  ███   ███     ┃
    ┃  ▄█████████▀    ███    █▀     ▄████▀   █▀    ▀█   █▀      ┃
    ┃                                                           ┃
    ┃                    ⟨ باطن ⟩                               ┃
    ┃            Revealing What Lies Beneath                    ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"#;

/// Print the startup banner with version info
pub fn print_banner() {
    println!("{}", BANNER.cyan().bold());
    println!(
        "  {}  {}",
        "Security-Hardened File Type Detection".bright_white(),
        format!("v{}", env!("CARGO_PKG_VERSION")).color(theme::ACCENT)
    );
    println!(
        "  {}",
        "Entropy Analysis • Polyglot Detection • Threat Scanning".color(theme::MUTED)
    );
    println!();
}

/// Print a styled section header
pub fn print_section(title: &str) {
    let line = "─".repeat(50);
    println!("\n{}", line.color(theme::MUTED));
    println!("  {} {}", "▶".color(theme::HEADER), title.bold());
    println!("{}", line.color(theme::MUTED));
}

/// Get threat level indicator with colored icon and label
#[allow(dead_code)] // Public console helper, not yet wired into all output paths.
pub fn threat_indicator(level: &ThreatLevel) -> ColoredString {
    match level {
        ThreatLevel::Safe => "✓ Safe".color(theme::SUCCESS),
        ThreatLevel::Suspicious => "⚠ Suspicious".color(theme::WARNING),
        ThreatLevel::Dangerous => "⚠ Dangerous".color(theme::DANGER).bold(),
        ThreatLevel::Critical => "✖ CRITICAL".color(theme::DANGER).bold().on_red(),
    }
}

/// Get threat level color for consistent styling
pub fn threat_color(level: &ThreatLevel) -> Color {
    match level {
        ThreatLevel::Safe => theme::SUCCESS,
        ThreatLevel::Suspicious => theme::WARNING,
        ThreatLevel::Dangerous => theme::DANGER,
        ThreatLevel::Critical => theme::DANGER,
    }
}

/// Get threat level icon
pub fn threat_icon(level: &ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Safe => "✓",
        ThreatLevel::Suspicious => "⚠",
        ThreatLevel::Dangerous => "⚠",
        ThreatLevel::Critical => "✖",
    }
}

/// Print a visual bar chart for threat distribution
pub fn print_threat_bar(label: &str, count: usize, total: usize, color: Color) {
    let percentage = if total > 0 {
        (count as f64 / total as f64 * 100.0) as usize
    } else {
        0
    };
    let bar_width = 20;
    let filled = (percentage * bar_width / 100).min(bar_width);
    let empty = bar_width - filled;

    let bar = format!(
        "{}{}",
        "█".repeat(filled).color(color),
        "░".repeat(empty).color(theme::MUTED)
    );

    println!(
        "  {:<12} {:>4} │{}│ {:>3}%",
        label.color(color),
        count.to_string().bold(),
        bar,
        percentage
    );
}

/// Format duration in human-readable format
pub fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();

    if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs > 0 {
        format!("{}.{}s", secs, millis / 100)
    } else {
        format!("{}ms", millis)
    }
}

/// Print scan statistics
pub fn print_stats(files: usize, duration: std::time::Duration) {
    let throughput = if duration.as_secs_f64() > 0.0 {
        files as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    println!(
        "  {} {} files in {}  {} {:.1} files/sec",
        "⏱".color(theme::INFO),
        files.to_string().bold(),
        format_duration(duration).color(theme::ACCENT),
        "⚡".color(theme::WARNING),
        throughput
    );
}

/// Print a separator line
pub fn print_separator() {
    println!("{}", "━".repeat(60).color(theme::MUTED));
}

/// Print colored message for different output types
pub fn print_info(msg: &str) {
    println!("{} {}", "ℹ".color(theme::INFO), msg);
}

pub fn print_success(msg: &str) {
    println!("{} {}", "✓".color(theme::SUCCESS), msg);
}

pub fn print_warning(msg: &str) {
    println!("{} {}", "⚠".color(theme::WARNING), msg);
}

pub fn print_error(msg: &str) {
    eprintln!("{} {}", "✖".color(theme::DANGER), msg.red());
}
