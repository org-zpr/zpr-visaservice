use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "zpt")]
#[command(version, verbatim_doc_comment)]
struct Cli {
    /// Path to a compiled ZPR policy.
    #[arg(value_name = "POLICY_BINARY")]
    policy: PathBuf,
}

fn main() {
    let exit_code = 0;
    let cli = Cli::parse();
    println!(
        "Policy binary path: {}",
        cli.policy.display().to_string().green()
    );
    std::process::exit(exit_code);
}
