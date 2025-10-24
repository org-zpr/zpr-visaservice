use clap::Parser;
use std::path::PathBuf;
use tracing::{Level, info};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

mod admin_service;
mod config;
mod error;

use crate::config::VSConfig;

/// vs - ZPR visa service
#[derive(Parser, Debug)]
#[command(name = "vs")]
#[command(version, verbatim_doc_comment)]
struct Cli {
    /// Initial policy file (.bin2 format)
    policy: PathBuf,

    /// Enable verbose debug output
    #[arg(short, long)]
    verbose: bool,

    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE", default_value = "vs.toml")]
    config: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    enable_logging(cli.verbose);
    info!("vs version {}", env!("CARGO_PKG_VERSION"));
    let config_file = cli.config.unwrap();
    let _cfg = match VSConfig::from_file(&config_file) {
        Ok(c) => {
            info!("using configuration: {}", config_file.display());
            c
        }
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };
    info!("exiting normally");
    std::process::exit(0);
}

fn enable_logging(verbose: bool) {
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            //.with(fmt::layer().with_thread_ids(true))
            .with(fmt::layer())
            .with(LevelFilter::from_level(level)),
    )
    .expect("failed to initialize logging");
}
