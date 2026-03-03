use clap::Parser;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use libeval::attribute::{ROLE_ADAPTER, key};
use libeval::pio;

mod actor_mgr;
mod admin_service;
mod assembly;
mod auth;
mod config;
mod connection_control;
mod counters;
mod db;
mod error;
mod event_mgr;
mod logging;
mod net_mgr;
mod policy_mgr;
mod signal_worker;
mod visa_mgr;
mod visareq_worker;
mod vsapi_worker;
mod vss_mgr;

#[cfg(test)]
mod test_helpers;

use crate::actor_mgr::ActorMgr;
use crate::admin_service::start_admin_server;
use crate::assembly::Assembly;
use crate::config::VSConfig;
use crate::connection_control::ConnectionControl;
use crate::db::DbConnection;
use crate::error::ServiceError;
use crate::event_mgr::EventMgr;
use crate::event_mgr::VsEvent;
use crate::logging::enable_logging;
use crate::logging::targets::MAIN;
use crate::net_mgr::NetMgr;
use crate::policy_mgr::PolicyMgr;
use crate::visa_mgr::VisaMgr;
use crate::vss_mgr::VssMgr;
use zpr::vsapi_types::Claim;

use redis::AsyncCommands;

const DEFAULT_CONFIG_PATH: &str = "vs.toml";

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

    /// Path to the configuration file. If "vs.toml" is present in the current directory, it will be used by default.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    enable_logging(cli.verbose);
    info!(target: MAIN, "vs version {}", env!("CARGO_PKG_VERSION"));
    let cfg = match load_config(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            error!(target: MAIN, "failed to load configuration: {}", e);
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

    let local_set = tokio::task::LocalSet::new();
    let _local_set_guard = local_set.enter();

    let vk_uri = cfg.core.vk_uri.as_deref().unwrap_or(config::VALKEY_URI);
    let vk_client = redis::Client::open(vk_uri).expect("failed to create ValKey redis client");
    info!(target: MAIN, "connecting to ValKey at {}...", vk_uri);

    let mut vk_conn = redis::aio::ConnectionManager::new(vk_client)
        .await
        .expect("failed to get redis connection");

    let res: String = vk_conn.ping().await.expect("failed to ping ValKey server");
    info!(target: MAIN, "connected to ValKey at {vk_uri}, ping response: {}", res);

    let db_handle = Arc::new(db::RedisDb::new(vk_conn));

    let mut js = JoinSet::new();

    let (vreq_tx, vreq_rx) =
        mpsc::channel::<visareq_worker::VisaRequestJob>(config::VISA_REQUEST_QUEUE_DEPTH);

    let actor_mgr = match create_actor_mgr(db_handle.clone()).await {
        Ok(adb) => adb,
        Err(e) => {
            error!(target: MAIN, "failed to instantiate actor database: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let policy_mgr_res =
        PolicyMgr::new_with_initial_policy(initial_policy, db::PolicyRepo::new(db_handle.clone()))
            .await;
    let policy_mgr = match policy_mgr_res {
        Ok(pm) => pm,
        Err(e) => {
            error!(target: MAIN, "failed to instantiate policy manager: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let visa_repo = db::VisaRepo::new(db_handle.clone());

    let (event_tx, event_rx) = mpsc::channel(config::EVENT_QUEUE_DEPTH);

    let asm = Arc::new(Assembly {
        config: cfg.clone(),
        counters: Default::default(),
        system_start_time: std::time::Instant::now(),
        cc: ConnectionControl::new(),
        policy_mgr: policy_mgr,
        actor_mgr: Arc::new(actor_mgr),
        state_db: db_handle,
        vreq_chan: vreq_tx,
        visa_mgr: VisaMgr::new(visa_repo),
        vss_mgr: VssMgr::new(),
        net_mgr: Arc::new(NetMgr::new_v6().await.expect("failed to create NetMgr")),
        event_mgr: EventMgr::new(event_tx),
    });

    js.spawn_local(signal_worker::launch(asm.clone()));
    js.spawn_local(event_mgr::launch(asm.clone(), event_rx));

    js.spawn_local(vsapi_worker::launch(
        asm.clone(),
        SocketAddr::new(
            cfg.get_vs_addr(),
            cfg.core.vsapi_port.unwrap_or(config::VSAPI_PORT),
        ),
    ));

    {
        let admin_key = cfg.core.admin_key.clone();
        let admin_cert = cfg.core.admin_cert.clone();
        let admin_listen = SocketAddr::new(
            cfg.get_vs_addr(),
            cfg.core.admin_port.unwrap_or(config::ADMIN_HTTPS_PORT),
        );
        let admin_asm = asm.clone();
        js.spawn_local(async move {
            start_admin_server(&admin_key, &admin_cert, admin_listen, &admin_asm).await;
        });
    }

    js.spawn_local(visareq_worker::launch_arena(
        asm.clone(),
        vreq_rx,
        config::MAX_VISA_REQUEST_WORKERS,
    ));

    // perform initial self-authorization
    if let Err(e) = self_authorize(asm.clone(), &cfg.get_vs_addr()).await {
        error!(target: MAIN, "self-authorization failed: {}", e);
        return std::process::ExitCode::FAILURE;
    }

    // TODO: Setup/launch the workers for the visa service. Those that will do the actual work
    // of generating visas, and all the housekeeping.

    local_set
        .run_until(async {
            while let Some(res) = js.join_next().await {
                res.unwrap();
            }
        })
        .await;

    info!(target: MAIN, "exiting");
    std::process::ExitCode::SUCCESS
}

/// Load configuration from an explicit path, the default path, or fall back to defaults.
fn load_config(explicit: Option<&std::path::Path>) -> Result<VSConfig, ServiceError> {
    match explicit {
        Some(path) => {
            let cfg = VSConfig::from_file(path)?;
            info!(target: MAIN, "using configuration: {}", path.display());
            Ok(cfg)
        }
        None => {
            let default_path = std::path::Path::new(DEFAULT_CONFIG_PATH);
            if default_path.exists() {
                let cfg = VSConfig::from_file(default_path)?;
                info!(target: MAIN, "using configuration: {}", default_path.display());
                Ok(cfg)
            } else {
                info!(target: MAIN, "no configuration file found, using defaults");
                Ok(VSConfig::default())
            }
        }
    }
}

async fn create_actor_mgr(dbh: Arc<dyn DbConnection>) -> Result<ActorMgr, ServiceError> {
    let adb = db::ActorRepo::new(dbh.clone());
    let ndb = db::NodeRepo::new(dbh);
    let mgr = ActorMgr::new(adb, ndb);
    Ok(mgr)
}

// TODO: This belongs somewhere else. Must be run every time we load a new policy.
//
// Also this "authorizes" the visa service actor by fiat, but we do not yet know what
// node the vs adapter is docked to.  We also have no way at the moment to tell the
// vs what node it is docked to.
//
// One idea is to query our local ph (via ph-cli) and get the substrate address of
// the docking node.  We can use that to find the node record.
//
async fn self_authorize(asm: Arc<Assembly>, vs_addr: &IpAddr) -> Result<(), ServiceError> {
    let mut claims = Vec::new();
    claims.push(Claim::new(key::ZPR_ADDR.into(), vs_addr.to_string()));
    claims.push(Claim::new(key::CN.into(), config::VS_CN.into()));
    claims.push(Claim::new(key::ROLE.into(), ROLE_ADAPTER.into()));

    let actor = asm
        .cc
        .authenticate_visa_service(asm.clone(), claims)
        .await?;

    asm.actor_mgr.add_adapter_no_node(&actor).await?;

    let evt = VsEvent::ActorJoins(vs_addr.clone());
    if let Err(e) = asm.event_mgr.record_event(evt).await {
        warn!(target: MAIN, "failed to record actor joins event for adapter {:?}: {}", actor.get_cn(), e);
    }

    Ok(())
}
