use ::polio::policy_capnp;
use bytes::Bytes;
use clap::Parser;
use colored::Colorize;
use libeval::zpr_policy::{ZprPolicy, ZprPolicyError};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZptError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("Invalid policy format: {0}")]
    InvalidFormat(String),
    #[error("ZPR policy error: {0}")]
    ZprPolicy(#[from] ZprPolicyError),
}

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

    let _zp = load_policy(&cli.policy).unwrap_or_else(|e| {
        eprintln!("{}: {e}", "Error loading policy".red());
        std::process::exit(1);
    });

    std::process::exit(0);
}

fn load_policy(path: &Path) -> Result<ZprPolicy, ZptError> {
    let encoded = std::fs::read(path)?;
    let encoded_container_bytes = Bytes::from(encoded);

    // The v2 binary format wraps a Policy struct inside a PolicyContainer struct.
    let container_reader = capnp::serialize::read_message(
        &mut std::io::Cursor::new(&encoded_container_bytes),
        capnp::message::ReaderOptions::new(),
    )?;

    let container = container_reader.get_root::<policy_capnp::policy_container::Reader>()?;

    // TODO: check compiler version?
    // TODO: check signature?

    if !container.has_policy() {
        return Err(ZptError::InvalidFormat(
            "policy container missing 'policy' field".to_string(),
        ));
    }
    let policy_bytes = container.get_policy().unwrap();
    let zp = ZprPolicy::new_from_policy_bytes(Bytes::copy_from_slice(policy_bytes))?;
    Ok(zp)
}
