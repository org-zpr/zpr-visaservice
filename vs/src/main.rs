use clap::Parser;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info};

use libeval::actor::Actor;
use libeval::attribute::{Attribute, ROLE_ADAPTER, key};
use libeval::pio;

mod actor_mgr;
mod admin_service;
mod assembly;
mod config;
mod connection_control;
mod cparam;
mod db;
mod error;
mod logging;
mod policy_mgr;
mod signal_worker;
mod visa_mgr;
mod visareq_worker;
mod vsapi_worker;
mod vss_mgr;

use crate::actor_mgr::ActorMgr;
use crate::admin_service::start_admin_server;
use crate::assembly::Assembly;
use crate::config::VSConfig;
use crate::connection_control::ConnectionControl;
use crate::error::VSError;
use crate::logging::enable_logging;
use crate::logging::targets::MAIN;
use crate::policy_mgr::PolicyMgr;
use crate::visa_mgr::VisaMgr;
use crate::vss_mgr::VssMgr;

use redis::AsyncCommands;

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

#[tokio::main]
async fn main() -> std::process::ExitCode {
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

    let local_set = tokio::task::LocalSet::new();
    let _local_set_guard = local_set.enter();

    let vk_uri = cfg.core.vk_uri.as_deref().unwrap_or(config::VALKEY_URI);
    let vk_client = redis::Client::open(vk_uri).expect("failed to create ValKey redis client");

    // TODO: Should I be creating this and saving it in assembly or or just keeping the client in assembly
    // and then getting connections when I want them?
    /*
    let mut vk_conn = vk_client
        .get_multiplexed_tokio_connection()
        .await
        .expect("failed to get redis connection");
    */
    let mut vk_conn = redis::aio::ConnectionManager::new(vk_client)
        .await
        .expect("failed to get redis connection");

    let res: String = vk_conn.ping().await.expect("failed to ping ValKey server");
    info!(target: MAIN, "connected to ValKey at {vk_uri}, ping response: {}", res);

    let db_handle = db::Handle::new(vk_conn);

    let mut js = JoinSet::new();

    let (vreq_tx, vreq_rx) =
        mpsc::channel::<visareq_worker::VisaRequestJob>(config::VISA_REQUEST_QUEUE_DEPTH);

    let actor_mgr = match create_actor_mgr(&db_handle, cfg.get_vs_addr()).await {
        Ok(adb) => adb,
        Err(e) => {
            error!(target: MAIN, "failed to instantiate actor database: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let policy_mgr_res =
        PolicyMgr::new_with_initial_policy(initial_policy, db::PolicyRepo::new(&db_handle)).await;
    let policy_mgr = match policy_mgr_res {
        Ok(pm) => pm,
        Err(e) => {
            error!(target: MAIN, "failed to instantiate policy manager: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let visa_repo = db::VisaRepo::new(&db_handle);

    let asm = Arc::new(Assembly {
        config: cfg.clone(),
        system_start_time: std::time::Instant::now(),
        cc: ConnectionControl::new(),
        policy_mgr: policy_mgr,
        actor_mgr: Arc::new(actor_mgr),
        state_db: db_handle,
        vreq_chan: vreq_tx,
        visa_mgr: VisaMgr::new(visa_repo),
        vss_mgr: VssMgr::new(),
    });

    js.spawn_local(signal_worker::launch(asm.clone()));

    js.spawn_local(vsapi_worker::launch(
        asm.clone(),
        SocketAddr::new(
            cfg.get_vs_addr(),
            cfg.core.vsapi_port.unwrap_or(config::VSAPI_PORT),
        ),
    ));

    let admin_asm = asm.clone();

    let rt_handle = tokio::runtime::Handle::current();
    js.spawn_blocking(move || {
        rt_handle.block_on(start_admin_server(
            &cfg.core.admin_key,
            &cfg.core.admin_cert,
            SocketAddr::new(
                cfg.get_vs_addr(),
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

async fn create_actor_mgr(dbh: &db::Handle, vs_addr: IpAddr) -> Result<ActorMgr, VSError> {
    let adb = db::ActorRepo::new(dbh);
    let ndb = db::NodeRepo::new(dbh);
    let mgr = ActorMgr::new(adb, ndb);
    // We are the visa service. As we say so it shall be.
    // The odd thing here is that we do not know what node we are connected to yet.
    let vs_actor = {
        let mut vsa = Actor::new();
        vsa.add_attribute(Attribute::builder(key::ZPR_ADDR).value(vs_addr.to_string()))?;
        vsa.add_attribute(Attribute::builder(key::CN).value(config::VS_CN))?;
        vsa.add_attribute(Attribute::builder(key::ROLE).value(ROLE_ADAPTER))?;
        vsa.add_attribute(
            Attribute::builder(key::SERVICES).value("/zpr/visaservice,/zpr/visaservice/admin"),
        )?;
        vsa.add_identity_key(0, key::CN)?;
        vsa
    };
    mgr.add_magic_adapter(&vs_actor).await?;
    Ok(mgr)
}
