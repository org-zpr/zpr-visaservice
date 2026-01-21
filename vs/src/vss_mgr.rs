use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::LocalSet;
use tokio_util::compat::*;
use tracing::{debug, error, info, warn};

use zpr::vsapi::v1;
use zpr::vsapi_types::{ApiResponseError, ServiceDescriptor, Visa};
use zpr::write_to::WriteTo;

use crate::assembly::Assembly;
use crate::config;
use crate::error::VSSError;
use crate::logging::targets::VSSMGR;

pub struct VssMgr {
    // Each node has an entry here, handle is a thread monitoring the nodes VSS.
    workers: DashMap<IpAddr, VssHandle>,

    // Only used to spin up VSS handlers.
    jobs_tx: mpsc::Sender<Job>,
}

#[derive(Clone)]
pub struct VssHandle {
    // For sending requests to a VSS handler thread (all the API calls)
    cmd_tx: mpsc::Sender<VssCmd>,
}

enum Job {
    // Params for starting a VssHandle thread.
    StartVssWorker {
        asm: Arc<Assembly>,
        vss_addr: SocketAddr,
        delay: std::time::Duration,
        cmd_rx: mpsc::Receiver<VssCmd>,
    },
}

type VssPushResponse = Result<usize, VSSError>; // usize is number items pushed.
type VssRevokeAuthResponse = Result<usize, VSSError>; // usize is number of items revoked.
type VssSetServicesResponse = Result<(), VSSError>;

// Each API call is expressed as a message using this enum.
#[allow(dead_code)]
enum VssCmd {
    Stop(),
    PushVisas(Vec<Visa>, oneshot::Sender<VssPushResponse>),
    RevokeVisasById(Vec<u64>, oneshot::Sender<VssPushResponse>),
    RevokeAuthsByZprAddr(Vec<IpAddr>, oneshot::Sender<VssRevokeAuthResponse>),
    SetServices(
        u64,
        Vec<ServiceDescriptor>,
        oneshot::Sender<VssSetServicesResponse>,
    ), // (version, services-descriptor-list, channel)
}

/// The Vss Manager manages VSS connections for each node.
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
    /// Once this starts, the first thing it does is send the services list across.
    /// It them will periodically ping the vss API.
    ///
    /// Error is returned if a worker is already running for the node. If that happens caller
    /// should use [VssMgr::get_handle] to obtain the existing handle and then call [VssHandle::stop].
    /// Note that it takes time for handle to respond to stop and clear out state in this manager.
    pub async fn start_vss_worker(
        &self,
        asm: Arc<Assembly>,
        vss_addr: &SocketAddr,
        delay: std::time::Duration,
    ) -> Result<(), VSSError> {
        let node_ip = vss_addr.ip();

        // Return error if we already have a worker for this node.
        if self.workers.contains_key(&node_ip) {
            return Err(VSSError::DuplicateWorker(*vss_addr));
        }

        let (cmd_tx, cmd_rx) = mpsc::channel::<VssCmd>(16);

        let job = Job::StartVssWorker {
            asm,
            vss_addr: *vss_addr,
            delay,
            cmd_rx,
        };
        let send_result = self.jobs_tx.try_send(job);
        if let Err(e) = send_result {
            return Err(VSSError::QueueFull(format!(
                "failed to queue VSS worker start job for {}: {}",
                vss_addr, e
            )));
        }
        let worker = VssHandle { cmd_tx };
        self.workers.insert(node_ip, worker);
        Ok(())
    }

    /// Obtain a handle to the VSS worker for the given node. Using the handle you can
    /// send VSS API messages.
    pub fn get_handle(&self, naddr: &IpAddr) -> Option<VssHandle> {
        self.workers.get(naddr).map(|h| h.clone())
    }

    /// Housekeeping function to remove (presumably stale/not-running) worker.
    /// Called when the worker run loop exists.
    ///
    /// TODO: May need a way to alert the system when the VSS worker stops unexpectedly.
    fn clear_handle(&self, naddr: &IpAddr) {
        self.workers.remove(naddr);
    }
}

/// Each VSS thread has a handle to it stored in the [VssMgr] `workers` map.
impl VssHandle {
    async fn send_command(&self, cmd: VssCmd) -> Result<(), VSSError> {
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| VSSError::ConnClosed)
    }

    /// Stop the worker.
    pub async fn stop(&self) -> Result<(), VSSError> {
        let cmd = VssCmd::Stop();
        self.send_command(cmd).await
    }

    /// Send visas to the node.
    #[allow(dead_code)]
    pub async fn push_visas(&self, visas: Vec<Visa>) -> Result<usize, VSSError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::PushVisas(visas, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSSError::ConnClosed)?
    }

    /// Revoke visas installed on the node by their IDs.
    #[allow(dead_code)]
    pub async fn revoke_visas(&self, ids: Vec<u64>) -> Result<usize, VSSError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::RevokeVisasById(ids, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSSError::ConnClosed)?
    }

    /// Revoke authorizations present on the node for the given zpr addresses.
    #[allow(dead_code)]
    pub async fn revoke_auths(&self, addrs: Vec<IpAddr>) -> Result<usize, VSSError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::RevokeAuthsByZprAddr(addrs, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSSError::ConnClosed)?
    }

    /// Tell the node about authentication services connected to the ZPRnet.
    #[allow(dead_code)]
    pub async fn set_services(
        &self,
        version: u64,
        services: Vec<ServiceDescriptor>,
    ) -> Result<(), VSSError> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let cmd = VssCmd::SetServices(version, services, resp_tx);
        self.send_command(cmd).await?;
        resp_rx.await.map_err(|_| VSSError::ConnClosed)?
    }
}

// This rather convoluted pattern for starting a vss worker is here because the capn proto
// rpc system must run in a tokio local task.
//
// See https://docs.rs/tokio/latest/tokio/task/struct.LocalSet.html#use-inside-tokiospawn
//
// There is only ever one "job" implementation -- the job that starts a VSS worker.
//
// This is called in a new thread.
async fn run_vss_job(job: Job) {
    match job {
        Job::StartVssWorker {
            asm,
            vss_addr,
            delay,
            cmd_rx,
        } => {
            debug!(target: VSSMGR, "starting VSS worker for node at {}", vss_addr);
            let naddr = vss_addr.ip().to_owned();
            tokio::time::sleep(delay).await;
            vss_worker_loop(asm.clone(), vss_addr, cmd_rx).await;
            // When we exit the worker loop, we are done but the handle is still sitting in
            // the manager. So we clean it out here:
            asm.vss_mgr.clear_handle(&naddr);
        }
    }
}

// Run-loop for a thread that manages a VSS connection to a node.
async fn vss_worker_loop(
    asm: Arc<Assembly>,
    node_addr: SocketAddr,
    mut cmd_rx: mpsc::Receiver<VssCmd>,
) {
    // Open connect to VSS.
    info!(target: VSSMGR, "connecting to VSS at {}", node_addr);

    // TODO: TLS
    let sock = match tokio::net::TcpStream::connect(node_addr).await {
        Ok(sock) => sock,
        Err(e) => {
            error!(target: VSSMGR, "failed to connect to VSS at {}: {}", node_addr, e);
            return; // TODO: How to signal manager?
        }
    };

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

    tokio::task::spawn_local(rpc_system);

    let req = vss_service.connect_request();

    let handle_result_rdr = match req.send().promise.await {
        Ok(req_resp) => req_resp,
        Err(e) => {
            error!(target: VSSMGR, "VSS connect request failed: {}", e);
            return; // TODO: Signal manager?
        }
    };

    let handle_result_ok_or_error = handle_result_rdr.get().unwrap().get_resp().unwrap();

    let vss_handle: v1::v_s_s_handle::Client = match handle_result_ok_or_error.which().unwrap() {
        v1::result::Which::Ok(vss_handle_obj) => vss_handle_obj.unwrap(),
        v1::result::Which::Error(err_obj) => {
            let err_obj = err_obj.unwrap();
            error!(target: VSSMGR, "VSS connect error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
            return; // TODO: Signal manager?
        }
    };

    info!(target: VSSMGR, "connected to VSS at {}", node_addr);

    match asm.actor_mgr.get_auth_services_list(asm.clone()).await {
        Ok(services) => {
            debug!(target: VSSMGR, "sending initial auth services list to VSS at {}", node_addr);
            if let Err(e) = do_set_services(&vss_handle, 1, services).await {
                error!(target: VSSMGR, "failed to send initial auth services list to VSS at {}: {}", node_addr, e);
            } else {
                debug!(target: VSSMGR, "initial auth services list sent to VSS at {}", node_addr);
            }
        }
        Err(e) => {
            warn!(target: VSSMGR, "failed to get auth services list for VSS at {}: {}", node_addr, e);
        }
    }

    let mut ping_interval = tokio::time::interval(config::VSS_PING_INTERVAL);

    loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    VssCmd::Stop() => {
                        info!(target: VSSMGR, "stop called on VSS worker for {}", node_addr);
                        break;
                    }
                    VssCmd::PushVisas(_visas, resp_tx) => {
                        if let Err(e) = resp_tx.send(Err(VSSError::InternalError("push-visas not implemented".to_string()))) {
                            error!(target: VSSMGR, "failed to send response for push-visas command: {:?}", e);
                        }
                    }
                    VssCmd::RevokeVisasById(_visa_id, resp_tx) => {
                        if let Err(e) = resp_tx.send(Err(VSSError::InternalError("revoke-visas not implemented".to_string()))) {
                            error!(target: VSSMGR, "failed to send response for revoke-visas command: {:?}", e);
                        }
                    }
                    VssCmd::RevokeAuthsByZprAddr(_zpr_addr, resp_tx) => {
                        if let Err(e) = resp_tx.send(Err(VSSError::InternalError("revoke-auths not implemented".to_string()))) {
                            error!(target: VSSMGR, "failed to send response for revoke-auths command: {:?}", e);
                        }
                    }
                    VssCmd::SetServices(_version, _services, resp_tx) => {
                        if let Err(e) = resp_tx.send(do_set_services(&vss_handle, _version, _services).await) {
                            error!(target: VSSMGR, "failed to send response for set-services command: {:?}", e);
                        }
                    }
                }
            }

            _ = ping_interval.tick() => {
                // TODO: We need some way to raise an alert to the manager when a ping fails.
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
                        v1::ok_or_error::Which::Error(err_rdr) => {
                            let err_obj = err_rdr.unwrap();
                            error!(target: VSSMGR, "VSS ping returns error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
                        }
                    }

                }
            }
        }
    }

    // Call ping in a loop periodically.  If this fails raise an alarm.
}

async fn do_set_services(
    vss_handle: &v1::v_s_s_handle::Client,
    version: u64,
    services: Vec<ServiceDescriptor>,
) -> Result<(), VSSError> {
    // The API calls for a "version" to be returned, but that is rather complicated
    // to manage here. So for now we just send version=1 always and leave it up to the node
    // to check the list and decide if anything has changed.
    // TODO: update the VSS API to use a different scheme here.

    let mut req = vss_handle.set_services_request();
    let mut req_builder = req.get();
    req_builder.set_version(version);

    let mut svc_list_builder = req_builder.init_svcs(services.len() as u32);
    for (i, svc) in services.iter().enumerate() {
        let mut svc_builder = svc_list_builder.reborrow().get(i as u32);
        svc.write_to(&mut svc_builder);
    }

    let set_response_rdr = req.send().promise.await?;

    let set_response_ok_or_err = set_response_rdr.get()?;

    match set_response_ok_or_err.get_res().unwrap().which().unwrap() {
        v1::ok_or_error::Which::Ok(_) => (),
        v1::ok_or_error::Which::Error(err_rdr) => {
            let api_err = ApiResponseError::try_from(err_rdr.unwrap())?;
            return Err(VSSError::from(api_err));
        }
    }

    Ok(())
}
