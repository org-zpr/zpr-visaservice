use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::LocalSet;
use tokio_util::compat::*;
use tracing::{debug, error, info, warn};

use zpr::vsapi::v1;
use zpr::vsapi_types::{ServiceDescriptor, Visa};

use crate::assembly::Assembly;
use crate::config;
use crate::error::VSError;
use crate::logging::targets::VSSMGR;

pub struct VssMgr {
    workers: DashMap<IpAddr, VssWorker>,
    jobs_tx: mpsc::Sender<Job>,
}

struct VssWorker {
    cancel_tx: oneshot::Sender<()>,
    cmd_tx: mpsc::Sender<VssCmd>,
}

enum Job {
    StartVssWorker {
        asm: Arc<Assembly>,
        vss_addr: SocketAddr,
        delay: std::time::Duration,
        cancel_rx: oneshot::Receiver<()>,
        cmd_rx: mpsc::Receiver<VssCmd>,
    },
}

pub enum VssCmd {
    PushVisa(Visa),
    RevokeVisaById(u64),
    RevokeAuthByZprAddr(IpAddr),
    SetServices(u64, Vec<ServiceDescriptor>), // (version, services-descriptor-list)
}

impl VssMgr {
    pub fn new() -> Self {
        let (jobs_tx, mut jobs_rx) = mpsc::channel(16);

        let rt = Builder::new_current_thread().enable_all().build().unwrap();

        std::thread::spawn(move || {
            let local = LocalSet::new();
            local.spawn_local(async move {
                while let Some(job) = jobs_rx.recv().await {
                    tokio::task::spawn_local(run_vss_job(job));
                }
            });
            rt.block_on(local);
        });

        VssMgr {
            workers: DashMap::new(),
            jobs_tx,
        }
    }

    /// Start a task to manage the VSS connection to a node.  Waits for `delay` before starting.
    ///
    pub fn start_vss_worker(
        &self,
        asm: Arc<Assembly>,
        vss_addr: &SocketAddr,
        delay: std::time::Duration,
    ) -> Result<(), VSError> {
        let node_ip = vss_addr.ip();

        // If a worker already exists for this IP, kill it before starting a new one.
        if let Some((_, old_worker)) = self.workers.remove(&node_ip) {
            let _ = old_worker.cancel_tx.send(());
            info!(target: VSSMGR, "stopping existing VSS worker for IP {}", node_ip);
        }

        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<VssCmd>(16);

        let job = Job::StartVssWorker {
            asm,
            vss_addr: *vss_addr,
            delay,
            cancel_rx,
            cmd_rx,
        };
        let send_result = self.jobs_tx.try_send(job);
        if let Err(e) = send_result {
            return Err(VSError::QueueFull(format!(
                "failed to queue VSS worker start job for {}: {}",
                vss_addr, e
            )));
        }
        let worker = VssWorker { cancel_tx, cmd_tx };
        self.workers.insert(node_ip, worker);
        Ok(())
    }

    /// Returns `true` if a worker was found and signalled to stop, `false` if no worker existed for the given IP.
    pub async fn stop_vss_worker(&self, vss_ip: &IpAddr) -> bool {
        if let Some((_, worker)) = self.workers.remove(vss_ip) {
            let _ = worker.cancel_tx.send(());
            info!(target: VSSMGR, "sent cancel to VSS worker for IP {}", vss_ip);
            true
        } else {
            false
        }
    }
}

// This rather convoluted pattern for starting a vss worker is here because the capn proto
// rpc system must run in a tokio local task.
//
// See https://docs.rs/tokio/latest/tokio/task/struct.LocalSet.html#use-inside-tokiospawn
async fn run_vss_job(job: Job) {
    match job {
        Job::StartVssWorker {
            asm,
            vss_addr,
            delay,
            cancel_rx,
            cmd_rx,
        } => {
            debug!(target: VSSMGR, "starting VSS worker for node at {}", vss_addr);
            tokio::time::sleep(delay).await;
            vss_worker_loop(asm, vss_addr, cancel_rx, cmd_rx).await;
        }
    }
}

async fn vss_worker_loop(
    _asm: Arc<Assembly>,
    node_addr: SocketAddr,
    mut cancel_rx: oneshot::Receiver<()>,
    mut cmd_rx: mpsc::Receiver<VssCmd>,
) {
    // Open connect to VSS.
    info!(target: VSSMGR, "connecting to VSS at {}", node_addr);

    // TODO: TLS
    let sock = tokio::net::TcpStream::connect(node_addr).await;
    if sock.is_err() {
        // ...
    }
    let sock = sock.unwrap();
    let (reader, writer) = sock.into_split();

    let network = capnp_rpc::twoparty::VatNetwork::new(
        tokio::io::BufReader::new(reader).compat(),
        tokio::io::BufWriter::new(writer).compat_write(),
        capnp_rpc::rpc_twoparty_capnp::Side::Client,
        capnp::message::ReaderOptions::new(),
    );

    let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);

    let vss_service: v1::visa_support_service::Client =
        rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);

    // TODO: Call set_services

    tokio::task::spawn_local(rpc_system);

    let req = vss_service.connect_request();

    let vss_request_response = req.send().promise.await;
    if vss_request_response.is_err() {
        // ...
    }

    let handle_result_rdr = vss_request_response.unwrap();
    let handle_result_ok_or_error = handle_result_rdr.get().unwrap().get_resp().unwrap();

    let vss_handle: v1::v_s_s_handle::Client = match handle_result_ok_or_error.which().unwrap() {
        v1::result::Which::Ok(vss_handle_obj) => vss_handle_obj.unwrap(),
        v1::result::Which::Error(err_obj) => {
            let err_obj = err_obj.unwrap();
            error!(target: VSSMGR, "VSS connect error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
            return;
        }
    };

    info!(target: VSSMGR, "connected to VSS at {}", node_addr);

    let mut ping_interval = tokio::time::interval(config::VSS_PING_INTERVAL);

    loop {
        tokio::select! {
            _ = &mut cancel_rx => {
                info!(target: VSSMGR, "VSS worker for {} received cancel", node_addr);
                break;
            }

            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    VssCmd::PushVisa(_visa) => warn!(target: VSSMGR, "VSS worker PushVisa not implemented yet"),
                    VssCmd::RevokeVisaById(_visa_id) => warn!(target: VSSMGR, "VSS worker RevokeVisaById not implemented yet"),
                    VssCmd::RevokeAuthByZprAddr(_zpr_addr) => warn!(target: VSSMGR, "VSS worker RevokeAuthByZprAddr not implemented yet"),
                    VssCmd::SetServices(_version, _services) => warn!(target: VSSMGR, "VSS worker SetServices not implemented yet"),
                }
            }

            _ = ping_interval.tick() => {
                let ping_req = vss_handle.ping_request();
                let ping_response_or_err = ping_req.send().promise.await;
                if ping_response_or_err.is_err() {
                    info!(target: VSSMGR, "ping to VSS at {} failed", node_addr);
                }
                else {
                    let ping_response_rdr = ping_response_or_err.unwrap();
                    let ping_response_ok_or_error = ping_response_rdr.get();
                    match ping_response_ok_or_error.unwrap().get_res().unwrap().which().unwrap() {
                        v1::ok_or_error::Which::Ok(_) => info!(target: VSSMGR, "ping to VSS at {} succeeded", node_addr),
                        v1::ok_or_error::Which::Error(err_obj) => {
                            let err_obj = err_obj.unwrap();
                            error!(target: VSSMGR, "VSS ping returns error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
                        }
                    }

                }
            }
        }
    }

    // Call ping in a loop periodically.  If this fails raise an alarm.
}
