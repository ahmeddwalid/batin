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
    pub mod signal;
    pub mod watcher;

    #[cfg(feature = "server")]
    pub mod serve;
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

    /// Output results in JSON format (shorthand for --format json)
    #[arg(long, global = true)]
    json: bool,

    /// Output results in CSV format (shorthand for --format csv)
    #[arg(long, global = true)]
    csv: bool,

    /// Output format
    #[arg(long, value_enum, global = true)]
    format: Option<CliFormat>,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Load and apply YARA rules from a file (requires the `yara` build feature)
    #[arg(long, global = true)]
    yara: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliFormat {
    Table,
    Json,
    Csv,
    Ndjson,
    Sarif,
    Html,
}

impl From<CliFormat> for cli::scanner::OutputFormat {
    fn from(f: CliFormat) -> Self {
        use cli::scanner::OutputFormat;
        match f {
            CliFormat::Table => OutputFormat::Table,
            CliFormat::Json => OutputFormat::Json,
            CliFormat::Csv => OutputFormat::Csv,
            CliFormat::Ndjson => OutputFormat::Ndjson,
            CliFormat::Sarif => OutputFormat::Sarif,
            CliFormat::Html => OutputFormat::Html,
        }
    }
}

impl Args {
    /// Resolve the effective output format from --format / --json / --csv.
    fn resolve_format(&self) -> cli::scanner::OutputFormat {
        use cli::scanner::OutputFormat;
        if let Some(f) = self.format {
            f.into()
        } else if self.json {
            OutputFormat::Json
        } else if self.csv {
            OutputFormat::Csv
        } else {
            OutputFormat::Table
        }
    }
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

        /// Recurse into archives (ZIP/TAR/tar.gz) and report nested entries
        #[arg(long)]
        scan_archives: bool,

        /// Maximum archive recursion depth
        #[arg(long, default_value_t = 4)]
        max_archive_depth: usize,

        /// Load additional signatures from a JSON file before scanning
        #[arg(long)]
        signatures: Option<PathBuf>,

        /// Number of files to detect concurrently (0 = automatic)
        #[arg(long, default_value_t = 0)]
        concurrency: usize,

        /// Flag files whose SHA-256 appears in this newline-delimited denylist
        #[arg(long)]
        hash_deny: Option<PathBuf>,
    },
    /// Watch a directory for new files
    Watch {
        /// Directory to watch
        path: PathBuf,
    },
    /// Generate shell completion scripts to stdout
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Generate a man page (roff) to stdout
    Man,
    /// Run an HTTP API daemon (requires the `server` build feature)
    Serve {
        /// Address to bind, e.g. 127.0.0.1:8080
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
    /// Look up a SHA-256 on VirusTotal (requires the `online` build feature)
    Reputation {
        /// SHA-256 hash to look up
        sha256: String,

        /// VirusTotal API key (falls back to the VT_API_KEY env var)
        #[arg(long)]
        api_key: Option<String>,
    },
}

/// Load a newline-delimited SHA-256 denylist file into a set.
///
/// Blank lines and `#` comments are ignored; hashes are lowercased.
fn load_hash_denylist(
    path: &std::path::Path,
) -> std::io::Result<std::collections::HashSet<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect())
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

    // Load YARA rules if requested.
    if let Some(ref yara_path) = args.yara {
        #[cfg(feature = "yara")]
        {
            match batin::register_yara_rules_from_file(yara_path) {
                Ok(()) => {
                    if args.verbose {
                        eprintln!("Loaded YARA rules from {}", yara_path.display());
                    }
                }
                Err(e) => {
                    eprintln!("Error loading YARA rules from {}: {e}", yara_path.display());
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(feature = "yara"))]
        {
            eprintln!(
                "Error: --yara requires building with the 'yara' feature (got {})",
                yara_path.display()
            );
            std::process::exit(1);
        }
    }

    let output_format = args.resolve_format();
    let verbose = args.verbose;

    match args.command {
        Some(Commands::Scan {
            path,
            recursive,
            output,
            exclude,
            min_threat,
            hash,
            scan_archives,
            max_archive_depth,
            signatures,
            concurrency,
            hash_deny,
        }) => {
            if let Some(sig_path) = signatures {
                match batin::load_user_signatures(&sig_path) {
                    Ok(n) => {
                        if verbose {
                            eprintln!("Loaded {n} custom signature(s) from {}", sig_path.display());
                        }
                    }
                    Err(e) => {
                        eprintln!("Error loading signatures from {}: {e}", sig_path.display());
                        std::process::exit(1);
                    }
                }
            }

            let deny = match hash_deny {
                Some(path) => match load_hash_denylist(&path) {
                    Ok(set) => set,
                    Err(e) => {
                        eprintln!("Error loading hash denylist from {}: {e}", path.display());
                        std::process::exit(1);
                    }
                },
                None => std::collections::HashSet::new(),
            };
            let needs_hash = hash || !deny.is_empty();

            let options = cli::scanner::ScanOptions {
                recursive,
                format: output_format,
                verbose,
                output,
                exclude,
                min_threat: min_threat.map(|t| t.into()),
                include_hash: needs_hash,
                scan_archives,
                max_archive_depth,
                concurrency,
                hash_deny: std::sync::Arc::new(deny),
            };
            cli::scanner::run_scan(path, options).await?;
        }
        Some(Commands::Watch { path }) => {
            cli::watcher::run_watch(path, verbose).await?;
        }
        Some(Commands::Completions { shell }) => {
            use clap::CommandFactory;
            let mut cmd = Args::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
        }
        Some(Commands::Man) => {
            use clap::CommandFactory;
            let man = clap_mangen::Man::new(Args::command());
            man.render(&mut std::io::stdout())?;
        }
        Some(Commands::Serve { addr }) => {
            #[cfg(feature = "server")]
            {
                cli::serve::run_serve(addr).await?;
            }
            #[cfg(not(feature = "server"))]
            {
                let _ = addr;
                eprintln!("Error: 'serve' requires building with the 'server' feature");
                std::process::exit(1);
            }
        }
        Some(Commands::Reputation { sha256, api_key }) => {
            #[cfg(feature = "online")]
            {
                let key = api_key
                    .or_else(|| std::env::var("VT_API_KEY").ok())
                    .unwrap_or_default();
                if key.is_empty() {
                    eprintln!("Error: provide --api-key or set VT_API_KEY");
                    std::process::exit(1);
                }
                match batin::reputation::virustotal_lookup(&sha256, &key) {
                    Ok(Some(rep)) => {
                        println!(
                            "{sha256}: malicious={} suspicious={} harmless={} undetected={}",
                            rep.malicious, rep.suspicious, rep.harmless, rep.undetected
                        );
                        if rep.is_flagged() {
                            std::process::exit(2);
                        }
                    }
                    Ok(None) => println!("{sha256}: not found on VirusTotal"),
                    Err(e) => {
                        eprintln!("Lookup failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            #[cfg(not(feature = "online"))]
            {
                let _ = (sha256, api_key);
                eprintln!("Error: 'reputation' requires building with the 'online' feature");
                std::process::exit(1);
            }
        }
        None => {
            // Direct mode - scan with default options (recursive enabled)
            if let Some(path) = args.input {
                let options = cli::scanner::ScanOptions {
                    recursive: true, // Enable recursive scanning by default
                    format: output_format,
                    verbose,
                    ..Default::default()
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
