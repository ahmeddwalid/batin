//! # Batin CLI
//!
//! Command-line interface for the Batin file type detection library.
//!
//! ## Features
//! - Analyze files for type, entropy, and threats
//! - JSON, CSV, and human-readable output formats
//! - Real-time directory watching
//! - Exclude patterns and threat level filtering
//!
//! ## Examples
//! ```bash
//! # Scan a directory recursively
//! batin scan ./files -r
//!
//! # Output in JSON format
//! batin scan document.pdf --json
//!
//! # Output in CSV format with hashes
//! batin scan ./files --csv --hash -o report.csv
//!
//! # Show only suspicious+ files
//! batin scan ./files --min-threat suspicious
//!
//! # Exclude patterns
//! batin scan ./files --exclude "*.txt" --exclude "*/node_modules/*"
//!
//! # Watch directory for new files
//! batin watch ./downloads
//! ```

mod cli {
    pub mod console;
    pub mod scanner;
    pub mod watcher;
}

use anyhow::Result;
use batin::ThreatLevel;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing::Level;

/// Batin - Security-hardened file type detection
///
/// Analyzes files using magic bytes, Shannon entropy, and advanced threat detection

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(subcommand_negates_reqs = true)]
#[command(args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Input file to analyze (shorthand for 'scan' - use subcommand for more options)
    #[arg(required = false)]
    input: Option<PathBuf>,

    /// Output results in JSON format
    #[arg(long, global = true)]
    json: bool,

    /// Output results in CSV format
    #[arg(long, global = true)]
    csv: bool,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Clone, Debug, ValueEnum)]
enum ThreatFilter {
    Safe,
    Suspicious,
    Dangerous,
    Critical,
}

impl From<ThreatFilter> for ThreatLevel {
    fn from(filter: ThreatFilter) -> Self {
        match filter {
            ThreatFilter::Safe => ThreatLevel::Safe,
            ThreatFilter::Suspicious => ThreatLevel::Suspicious,
            ThreatFilter::Dangerous => ThreatLevel::Dangerous,
            ThreatFilter::Critical => ThreatLevel::Critical,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a file or directory
    Scan {
        /// Input path
        path: PathBuf,

        /// Recursive scanning
        #[arg(short, long)]
        recursive: bool,

        /// Output file for results
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Exclude files matching glob patterns
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Minimum threat level to show
        #[arg(long, value_enum)]
        min_threat: Option<ThreatFilter>,

        /// Include file hashes (MD5, SHA-256)
        #[arg(long)]
        hash: bool,
    },
    /// Watch a directory for new files
    Watch {
        /// Directory to watch
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    match args.command {
        Some(Commands::Scan {
            path,
            recursive,
            output,
            exclude,
            min_threat,
            hash,
        }) => {
            let options = cli::scanner::ScanOptions {
                recursive,
                json: args.json,
                csv: args.csv,
                verbose: args.verbose,
                output,
                exclude,
                min_threat: min_threat.map(|t| t.into()),
                include_hash: hash,
            };
            cli::scanner::run_scan(path, options).await?;
        }
        Some(Commands::Watch { path }) => {
            cli::watcher::run_watch(path, args.verbose).await?;
        }
        None => {
            // Direct mode - scan with default options (recursive enabled)
            if let Some(path) = args.input {
                let options = cli::scanner::ScanOptions {
                    recursive: true, // Enable recursive scanning by default
                    json: args.json,
                    csv: args.csv,
                    verbose: args.verbose,
                    output: None,
                    exclude: Vec::new(),
                    min_threat: None,
                    include_hash: false,
                };
                cli::scanner::run_scan(path, options).await?;
            } else {
                // No input provided - show help
                eprintln!("Error: No input file or directory provided.");
                eprintln!("Usage: batin <INPUT> or batin scan <PATH> [OPTIONS]");
                eprintln!("Try 'batin --help' for more information.");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
