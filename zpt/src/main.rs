mod error;
mod parser;
mod pio;
mod repl;
mod zmachine;

use clap::Parser;
use colored::Colorize;
use std::path::{Path, PathBuf};
use tracing::Level;
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

use crate::repl::Repl;
use error::ZptError;

#[derive(Parser, Debug)]
#[command(name = "zpt")]
#[command(version, verbatim_doc_comment)]
struct Cli {
    /// Path to a ZPT instructions file.
    #[arg(short, long, value_name = "INSTRUCTIONS")]
    input: Option<PathBuf>,

    /// Enable the the log output from libeval
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    if cli.verbose {
        enable_logger();
    }
    if cli.input.is_none() {
        match Repl::new().run() {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}: {e}", "Error".red());
                std::process::exit(1);
            }
        };
    } else {
        let input = cli.input.as_ref().unwrap();
        match run_file(input) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}: {e}", "Error".red());
                std::process::exit(1);
            }
        };
    }
    std::process::exit(0);
}

fn run_file(input: &Path) -> Result<(), ZptError> {
    println!(
        "loading instructions from: {}",
        input.to_string_lossy().green()
    );

    /*
    let _zp = load_policy(&cli.policy).unwrap_or_else(|e| {
        eprintln!("{}: {e}", "Error loading policy".red());
        std::process::exit(1);
    });
    */

    Ok(())
}

fn enable_logger() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_thread_ids(true))
        .with(LevelFilter::from_level(Level::DEBUG))
        .init();
}
