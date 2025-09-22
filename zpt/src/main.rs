use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use libeval::zpr_policy::ZprPolicy;

#[derive(Parser, Debug)]
#[command(name = "zpt")]
#[command(version, verbatim_doc_comment)]
struct Cli {
    /// Path to a compiled ZPR policy.
    #[arg(short, long, value_name = "POLICY_BINARY")]
    policy: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    println!(
        "Policy binary path: {}",
        cli.policy.to_string_lossy().green()
    );

    let _zp = ZprPolicy::new_from_file(&cli.policy).unwrap_or_else(|e| {
        eprintln!("{}: {e}", "Error loading policy".red());
        std::process::exit(1);
    });

    std::process::exit(0);
}
