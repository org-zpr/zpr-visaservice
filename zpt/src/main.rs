mod error;
mod parser;
mod pio;
mod repl;
mod zmachine;

use clap::Parser;
use colored::Colorize;

use std::env;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use tracing::Level;
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

use crate::repl::Repl;
use error::ZptError;

/// ZPT - ZPR Policy Tester
///
/// A command-line tool to test policies against specific communication patterns.
///
/// You can run this interactively (default) or provide a file (or STDIN) with
/// ZPT instructions.
#[derive(Parser, Debug)]
#[command(name = "zpt")]
#[command(version, verbatim_doc_comment)]
struct Cli {
    /// Path to a ZPT instructions file (use '-' for stdin)
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
    let cwd = env::current_dir().unwrap_or(PathBuf::from("."));
    if cli.input.is_none() {
        match Repl::new(&cwd).run() {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}: {e}", "Error".red());
                std::process::exit(1);
            }
        };
    } else {
        let input = cli.input.as_ref().unwrap();
        match run_file_or_stdin(input, &cwd) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}: {e}", "Error".red());
                std::process::exit(1);
            }
        };
    }
    std::process::exit(0);
}

fn run_file_or_stdin(input: &Path, cwd: &Path) -> Result<(), ZptError> {
    let instructions = if input.to_string_lossy() == "-" {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        buffer
    } else {
        std::fs::read_to_string(input)?
    };
    let base_path = if let Some(parent) = input.parent() {
        parent.to_path_buf()
    } else {
        cwd.to_path_buf()
    };
    Repl::new(&base_path).run_script(instructions.lines())
}

fn enable_logger() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_thread_ids(true))
        .with(LevelFilter::from_level(Level::DEBUG))
        .init();
}
