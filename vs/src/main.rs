use clap::Parser;
use redis::AsyncCommands;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{Level, error, info};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

mod admin_service;
mod assembly;
mod config;
mod error;
mod logging;
mod signal_worker;
mod vsapi_worker;
mod zpr;

use crate::admin_service::start_admin_server;
use crate::assembly::Assembly;
use crate::config::VSConfig;
use crate::logging::enable_logging;
use crate::logging::targets::MAIN;

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
    info!(target: MAIN, "vs version {}", env!("CARGO_PKG_VERSION"));
    let config_file = cli.config.unwrap();
    let cfg = match VSConfig::from_file(&config_file) {
        Ok(c) => {
            info!(target: MAIN, "using configuration: {}", config_file.display());
            c
        }
        Err(e) => {
            error!(target: MAIN, "Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    let asm = Arc::new(Assembly::new());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let _runtime_guard = runtime.enter();

    let local_set = tokio::task::LocalSet::new();
    let _local_set_guard = local_set.enter();

    // ValKey
    // Just go through steps to get a connection. Placeholder since we don't know
    // where we need it yet.

    let vk_uri = cfg.core.vk_uri.as_deref().unwrap_or(zpr::VALKEY_URI);
    let _vk_client = redis::Client::open(vk_uri).expect("failed to create ValKey redis client");
    let res = runtime.block_on(async { _vk_client.create_multiplexed_tokio_connection().await });
    match res {
        Ok(_conn) => {
            info!(target: MAIN, "connected to ValKey at {vk_uri}");
        }
        Err(e) => {
            error!(target: MAIN, "failed to connect to ValKey at {vk_uri}: {}", e);
            std::process::exit(1);
        }
    }

    let mut js = JoinSet::new();
    js.spawn_local(signal_worker::launch(asm.clone()));

    let rt_handle = runtime.handle().clone();
    js.spawn_blocking(move || {
        rt_handle.block_on(start_admin_server(
            &cfg.core.admin_key,
            &cfg.core.admin_cert,
            SocketAddr::new(
                cfg.core.vs_addr.unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                cfg.core.admin_port.unwrap_or(zpr::ADMIN_HTTPS_PORT),
            ),
            &asm,
        ));
    });

    local_set.block_on(&runtime, async {
        while let Some(res) = js.join_next().await {
            res.unwrap();
        }
    });

    info!(target: MAIN, "exiting");
    std::process::exit(0);
}
