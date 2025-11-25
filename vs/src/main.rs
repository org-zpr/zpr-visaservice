use clap::Parser;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info};

use libeval::pio;

mod actor_db;
mod admin_service;
mod assembly;
mod config;
mod connection_control;
mod cparam;
mod error;
mod logging;
mod policy_mgr;
mod signal_worker;
mod visa_mgr;
mod visareq_worker;
mod vsapi_worker;

use crate::actor_db::ActorDb;
use crate::admin_service::start_admin_server;
use crate::assembly::Assembly;
use crate::config::VSConfig;
use crate::connection_control::ConnectionControl;
use crate::logging::enable_logging;
use crate::logging::targets::MAIN;
use crate::policy_mgr::PolicyMgr;
use crate::visa_mgr::VisaMgr;

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

fn main() -> std::process::ExitCode {
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
            return std::process::ExitCode::FAILURE;
        }
    };

    let initial_policy = match pio::load_policy(
        &cli.policy,
        pio::Version(
            config::POLICY_MIN_COMPILER_MAJOR,
            config::POLICY_MIN_COMPILER_MINOR,
            config::POLICY_MIN_COMPILER_PATCH,
        ),
    ) {
        Ok(p) => p,
        Err(e) => {
            error!(target: MAIN, "failed to load initial policy from {}: {}", cli.policy.display(), e);
            return std::process::ExitCode::FAILURE;
        }
    };

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

    let vk_uri = cfg.core.vk_uri.as_deref().unwrap_or(config::VALKEY_URI);
    let vk_client = redis::Client::open(vk_uri).expect("failed to create ValKey redis client");
    let res = runtime.block_on(async { vk_client.create_multiplexed_tokio_connection().await });
    let (vk_conn, vk_fut) = match res {
        Ok((conn, fut)) => {
            info!(target: MAIN, "connected to ValKey at {vk_uri}");
            (conn, fut)
        }
        Err(e) => {
            error!(target: MAIN, "failed to connect to ValKey at {vk_uri}: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let (vreq_tx, vreq_rx) =
        mpsc::channel::<visareq_worker::VisaRequestJob>(config::VISA_REQUEST_QUEUE_DEPTH);

    let asm = Arc::new(Assembly {
        system_start_time: std::time::Instant::now(),
        cc: ConnectionControl::new(),
        policy_mgr: PolicyMgr::new_with_initial_policy(initial_policy),
        actor_db: ActorDb::new(),
        vk_conn: Arc::new(vk_conn),
        vreq_chan: vreq_tx,
        visa_mgr: VisaMgr::new(),
    });

    let mut js = JoinSet::new();

    js.spawn(vk_fut); // runs redis

    js.spawn_local(signal_worker::launch(asm.clone()));

    js.spawn_local(vsapi_worker::launch(
        asm.clone(),
        SocketAddr::new(
            cfg.core.vs_addr.unwrap_or(IpAddr::V6(config::VS_ZPR_ADDR)),
            cfg.core.vsapi_port.unwrap_or(config::VSAPI_PORT),
        ),
    ));

    let rt_handle = runtime.handle().clone();
    let admin_asm = asm.clone();
    js.spawn_blocking(move || {
        rt_handle.block_on(start_admin_server(
            &cfg.core.admin_key,
            &cfg.core.admin_cert,
            SocketAddr::new(
                cfg.core.vs_addr.unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                cfg.core.admin_port.unwrap_or(config::ADMIN_HTTPS_PORT),
            ),
            &admin_asm,
        ));
    });

    js.spawn_local(visareq_worker::launch_arena(
        asm.clone(),
        vreq_rx,
        config::MAX_VISA_REQUEST_WORKERS,
    ));

    // TODO: Setup/launch the workers for the visa service. Those that will do the actual work
    // of generating visas, and all the housekeeping.

    local_set.block_on(&runtime, async {
        while let Some(res) = js.join_next().await {
            res.unwrap();
        }
    });

    info!(target: MAIN, "exiting");
    std::process::ExitCode::SUCCESS
}
