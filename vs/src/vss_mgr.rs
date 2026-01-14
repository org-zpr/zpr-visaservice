use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{error, info};

use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::*;
use zpr::vsapi::v1;

use crate::assembly::Assembly;
use crate::error::VSError;
use crate::logging::targets::VSSMGR;

pub struct VssMgr {
    workers: DashMap<IpAddr, JoinHandle<()>>,
}

impl VssMgr {
    pub fn new() -> Self {
        VssMgr {
            workers: DashMap::new(),
        }
    }

    /// Arrange to kick off a vss worker loop which will wait `delay` before starting.
    pub fn start_vss_worker(
        &self,
        asm: Arc<Assembly>,
        vss_addr: &std::net::SocketAddr,
        delay: std::time::Duration,
    ) -> Result<(), VSError> {
        let node_addr = *vss_addr;
        let node_ip = node_addr.ip();
        if self.workers.contains_key(&node_ip) {
            return Err(VSError::DuplicateNode(format!(
                "VSS worker for node at IP {} already exists",
                node_ip
            )));
        }

        let asm = asm.clone();
        let jh = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            vss_worker_loop(asm, node_addr).await;
        });
        self.workers.insert(node_addr.ip(), jh);
        Ok(())
    }

    /// Calls to abort the vss worker thread, but task may take some time to stop though
    /// this returns immediately.
    pub fn stop_vss_worker(&self, node_ip: &IpAddr) {
        if let Some((_, jh)) = self.workers.remove(node_ip) {
            jh.abort();
        }
    }
}

async fn vss_worker_loop(asm: Arc<Assembly>, node_addr: SocketAddr) {
    // Implementation of the VSS worker loop that handles communication with the VSS.
    // This is a placeholder for the actual logic.

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

    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(rpc_system);

            let mut req = vss_service.connect_request();
            let req_bldr = req.get().init_req();

            let vss_request_response = req.send().promise.await;
            if vss_request_response.is_err() {
                // ...
            }

            let handle_result_a = vss_request_response
                .unwrap();

                let handle_result_b = handle_result_a
                .get()
                .unwrap()
                .get_resp()
                .unwrap();

            let vss_handle: v1::v_s_s_handle::Client = match handle_result_b.which().unwrap() {
                v1::result::Which::Ok(vss_handle_obj) => vss_handle_obj.unwrap(),
                v1::result::Which::Error(err_obj) => {
                    let err_obj = err_obj.unwrap();
                    error!(target: VSSMGR, "VSS connect error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
                    return;
                }
            };


            info!(target: VSSMGR, "connected to VSS at {}", node_addr);

            let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = ping_interval.tick() => {
                        let ping_req = vss_handle.ping_request();
                        let ping_response_or_err = ping_req.send().promise.await;
                        if ping_response_or_err.is_err() {
                            info!(target: VSSMGR, "ping to VSS at {} failed", node_addr);
                        }
                        else {
                            let ping_response_a = ping_response_or_err.unwrap();

                            let ping_response_b = ping_response_a.get();

                            match ping_response_b.unwrap().get_res().unwrap().which().unwrap() {
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
        })
        .await;

    // Call ping in a loop periodically.  If this fails raise an alarm.
}
