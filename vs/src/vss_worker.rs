//! Each node's VSS service is managed by a worker here on the VS side.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_util::compat::*;
use tracing::{debug, error, info, trace, warn};

use zpr::policy_types::{NetAddr, NetworkHost};
use zpr::vsapi::v1;
use zpr::vsapi_types::{
    ApiResponseError, Link, LinkRole, Param, ServiceDescriptor, SockAddr, pname,
};
use zpr::write_to::WriteTo;

use libeval::policy::Peer;

use crate::assembly::Assembly;
use crate::config;
use crate::counters::CounterType;
use crate::error::{ResolverError, VssSyncError};
use crate::logging::targets::VSS;
use crate::net_mgr;
use crate::vss::VssCmd;

/// Default timeout for a single Cap'n Proto RPC call.
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum (and initial) timeout for a ping RPC call.
const PING_MIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct VssState {
    last_configure: Option<Instant>,
    last_set_services: Option<Instant>,
    last_set_topology: Option<Instant>,
    last_services_update: Instant,
    last_topology_update: Instant,
}

impl VssState {
    fn default() -> Self {
        VssState {
            last_configure: None,
            last_set_services: None,
            last_set_topology: None,
            last_services_update: Instant::now(),
            last_topology_update: Instant::now(),
        }
    }

    fn needs_set_services(&self) -> bool {
        self.last_set_services.is_none()
            || self.last_services_update > self.last_set_services.unwrap()
    }

    fn needs_set_topology(&self) -> bool {
        self.last_set_topology.is_none()
            || self.last_topology_update > self.last_set_topology.unwrap()
    }
}

/// Wrap a Cap'n Proto RPC future with a timeout, mapping errors.
async fn rpc_with_timeout<F, T>(
    name: &'static str,
    duration: Duration,
    fut: F,
) -> Result<T, VssSyncError>
where
    F: Future<Output = Result<T, capnp::Error>>,
{
    match tokio::time::timeout(duration, fut).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(capnp_err)) => Err(capnp_err.into()),
        Err(_elapsed) => Err(VssSyncError::Timeout(name.to_string())),
    }
}

// Run-loop for a thread that manages a VSS connection to a node.
pub async fn vss_worker_loop(
    asm: Arc<Assembly>,
    node_addr: SocketAddr,
    mut cmd_rx: mpsc::Receiver<VssCmd>,
) {
    // Open connect to VSS.
    info!(target: VSS, "connecting to VSS at {}", node_addr);

    let mut state = VssState::default();

    let sock = match tokio::net::TcpStream::connect(node_addr).await {
        Ok(sock) => sock,
        Err(e) => {
            error!(target: VSS, "failed to connect to VSS at {}: {}", node_addr, e);
            asm.counters.incr(CounterType::VssErrors);
            return; // TODO: How to signal manager?
        }
    };

    let connector = tls_connect();
    let tls = connector
        .connect(node_addr.ip().into(), sock)
        .await
        .unwrap();
    let (reader, writer) = tokio::io::split(tls);

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

    let handle_result_rdr =
        match rpc_with_timeout("connect", DEFAULT_RPC_TIMEOUT, req.send().promise).await {
            Ok(req_resp) => req_resp,
            Err(e) => {
                error!(target: VSS, "VSS connect request failed: {}", e);
                asm.counters.incr(CounterType::VssErrors);
                return; // TODO: Signal manager?
            }
        };

    let handle_result_ok_or_error = handle_result_rdr.get().unwrap().get_resp().unwrap();

    let vss_handle: v1::v_s_s_handle::Client = match handle_result_ok_or_error.which().unwrap() {
        v1::result::Which::Ok(vss_handle_obj) => vss_handle_obj.unwrap(),
        v1::result::Which::Error(err_obj) => {
            let err_obj = err_obj.unwrap();
            error!(target: VSS, "VSS connect error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
            asm.counters.incr(CounterType::VssErrors);
            return; // TODO: Signal manager?
        }
    };

    info!(target: VSS, "now connected to VSS at {}", node_addr);

    do_vss_initialization(&mut state, &asm, &node_addr.ip(), &vss_handle).await;

    let ping_timeout = tokio::time::sleep(config::VSS_PING_INTERVAL);
    tokio::pin!(ping_timeout);
    let mut ping_failures = 0;

    let mut heartbeat = tokio::time::interval(config::VSS_HEARTBEAT_INTERVAL);

    loop {
        tokio::select! {
            cmd_opt = cmd_rx.recv() => {
                match cmd_opt {
                    Some(cmd) => match cmd {
                        VssCmd::Stop() => {
                            info!(target: VSS, "stop called on VSS worker for {}", node_addr);
                            break;
                        }
                        VssCmd::PushVisas(_visas, resp_tx) => {
                            if let Err(e) = resp_tx.send(Err(VssSyncError::Internal("push-visas not implemented".to_string()))) {
                                error!(target: VSS, "failed to send response for push-visas command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::RevokeVisasById(_visa_id, resp_tx) => {
                            if let Err(e) = resp_tx.send(Err(VssSyncError::Internal("revoke-visas not implemented".to_string()))) {
                                error!(target: VSS, "failed to send response for revoke-visas command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::RevokeAuthsByZprAddr(_zpr_addr, resp_tx) => {
                            if let Err(e) = resp_tx.send(Err(VssSyncError::Internal("revoke-auths not implemented".to_string()))) {
                                error!(target: VSS, "failed to send response for revoke-auths command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::SetServices(services, resp_tx) => {
                            if let Err(e) = resp_tx.send(do_set_services(&vss_handle, services).await) {
                                error!(target: VSS, "failed to send response for set-services command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::Configure(params, resp_tx) => {
                            if let Err(e) = resp_tx.send(do_configure(&vss_handle, params).await) {
                                error!(target: VSS, "failed to send response for configure command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                    }
                    None => {
                        // Uh oh - channel closed.
                        warn!(target: VSS, "command channel closed for VSS worker for {}", node_addr);
                        break;
                    }
                }
            }

            _ = heartbeat.tick() => {
                do_housekeeping(&mut state, &asm, &node_addr.ip(), &vss_handle).await;
            }

            () = &mut ping_timeout => {
                let ping_dur = PING_MIN_TIMEOUT + Duration::from_secs(ping_failures);
                match rpc_with_timeout("ping", ping_dur, vss_handle.ping_request().send().promise).await {
                    Ok(ping_response_rdr) => {
                        match ping_response_rdr.get().unwrap().get_res().unwrap().which().unwrap() {
                            v1::ok_or_error::Which::Ok(_) => {
                                trace!(target: VSS, "ping to VSS at {} succeeded", node_addr);
                                asm.actor_mgr.update_node_last_seen(&node_addr.ip()).await.ok(); // Ignore errors.
                                ping_failures = 0;
                            }
                            v1::ok_or_error::Which::Error(err_rdr) => {
                                let err_obj = err_rdr.unwrap();
                                error!(target: VSS, "VSS ping returns error: code={:?} msg={:?}", err_obj.get_code(), err_obj.get_message());
                                asm.counters.incr(CounterType::VssErrors);
                                // TODO: What does this even mean? We got a reply but it is a coded error message? Should we just disconnect from node?
                                ping_failures += 1;
                            }
                        }
                    }
                    Err(VssSyncError::Timeout(_)) => {
                        warn!(target: VSS, "ping to VSS at {} timed out", node_addr);
                        asm.counters.incr(CounterType::VssErrors);
                        ping_failures += 1;
                    }
                    Err(_) => {
                        warn!(target: VSS, "ping to VSS at {} failed", node_addr);
                        asm.counters.incr(CounterType::VssErrors);
                        ping_failures += 1;
                    }
                }
                if ping_failures == 0 {
                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + config::VSS_PING_INTERVAL);
                } else if ping_failures < config::VSS_MAX_PING_FAILURES as u64 {
                    ping_timeout.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(1));
                } else {
                    error!(target: VSS, "too many VSS ping failures to {}, exiting VSS worker", node_addr);
                    return;
                }
            }
        }
    }
}

async fn do_housekeeping(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    if state.last_configure.is_none() {
        send_configure(state, asm, node_addr, vss_handle).await;
    }
    if state.needs_set_services() {
        send_services(state, asm, node_addr, vss_handle).await;
    }
    if state.needs_set_topology() {
        send_topology(state, asm, node_addr, vss_handle).await;
    }

    // TODO: Check for pending visas and revocations. And if found, send them.
}

/// When the vss worker starts up the node expects a couple of calls immediately.
///
/// 1. `configure()` to set the params (only AAA prefix for now).
/// 2. `setServices()` to tell node about the available auth services.
///
/// And, if the node is supposed to have peers, we call:
///
/// 3. `setTopology()` to tell node about its links.
///
async fn do_vss_initialization(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    send_configure(state, asm, node_addr, vss_handle).await;
    send_services(state, asm, node_addr, vss_handle).await;
    send_topology(state, asm, node_addr, vss_handle).await;
}

async fn send_configure(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    // The AAA net is stored in the actor properties, but it is statically tied to
    // the node ZPR address so we just recompute it here.
    let aaa_net = net_mgr::aaa_network_for_node(node_addr);
    let params = vec![Param::new_str(
        pname::AAA_PREFIX.into(),
        aaa_net.to_string(),
    )];
    debug!(target: VSS, "sending configure to VSS at {node_addr}");
    match do_configure(vss_handle, params).await {
        Ok(_) => {
            debug!(target: VSS, "{node_addr} configured successfully");
            state.last_configure = Some(Instant::now());
        }
        Err(e) => {
            warn!(target: VSS, "failed to configure VSS at {node_addr}: {e}");
            asm.counters.incr(CounterType::VssErrors);
        }
    }
}

async fn send_services(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    match asm.actor_mgr.get_auth_services_list(asm.clone()).await {
        Ok(services) => {
            debug!(target: VSS, "sending initial auth services list to VSS at {}", node_addr);
            if let Err(e) = do_set_services(&vss_handle, services).await {
                error!(target: VSS, "failed to send initial auth services list to VSS at {}: {}", node_addr, e);
                asm.counters.incr(CounterType::VssErrors);
            } else {
                debug!(target: VSS, "initial auth services list sent to VSS at {}", node_addr);
                state.last_set_services = Some(Instant::now());
            }
        }
        Err(e) => {
            warn!(target: VSS, "failed to get auth services list for VSS at {}: {}", node_addr, e);
        }
    }
}

async fn send_topology(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    let cpol = asm.policy_mgr.get_current();
    let peers = cpol.get_peers_for_node(node_addr);
    let links = peers_to_links(peers.unwrap_or(&[])).await;
    drop(cpol);

    debug!(target: VSS, "sending initial topology to VSS at {}", node_addr);
    if let Err(e) = do_set_topology(vss_handle, &links).await {
        error!(target: VSS, "failed to send initial topology to VSS at {}: {}", node_addr, e);
        asm.counters.incr(CounterType::VssErrors);
    } else {
        debug!(target: VSS, "initial topology sent to VSS at {}", node_addr);
        state.last_set_topology = Some(Instant::now());
    }
}

async fn do_set_services(
    vss_handle: &v1::v_s_s_handle::Client,
    services: Vec<ServiceDescriptor>,
) -> Result<(), VssSyncError> {
    let mut req = vss_handle.set_services_request();
    let req_builder = req.get();

    let mut svc_list_builder = req_builder.init_svcs(services.len() as u32);
    for (i, svc) in services.iter().enumerate() {
        let mut svc_builder = svc_list_builder.reborrow().get(i as u32);
        svc.write_to(&mut svc_builder);
    }

    let set_response_rdr =
        rpc_with_timeout("set-services", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    let set_response_ok_or_err = set_response_rdr.get()?;

    match set_response_ok_or_err.get_res().unwrap().which().unwrap() {
        v1::ok_or_error::Which::Ok(_) => (),
        v1::ok_or_error::Which::Error(err_rdr) => {
            let api_err = ApiResponseError::try_from(err_rdr.unwrap())?;
            return Err(VssSyncError::from(api_err));
        }
    }

    Ok(())
}

async fn do_configure(
    vss_handle: &v1::v_s_s_handle::Client,
    params: Vec<Param>,
) -> Result<(), VssSyncError> {
    let mut req = vss_handle.configure_request();
    let req_builder = req.get();

    let mut params_builder = req_builder.init_params(params.len() as u32);
    for (i, param) in params.iter().enumerate() {
        let mut param_builder = params_builder.reborrow().get(i as u32);
        param.write_to(&mut param_builder);
    }

    let configure_response_rdr =
        rpc_with_timeout("configure", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    let configure_response_ok_or_err = configure_response_rdr.get()?;

    match configure_response_ok_or_err
        .get_res()
        .unwrap()
        .which()
        .unwrap()
    {
        v1::ok_or_error::Which::Ok(_) => Ok(()),
        v1::ok_or_error::Which::Error(err_rdr) => {
            let api_err = ApiResponseError::try_from(err_rdr.unwrap())?;
            Err(VssSyncError::from(api_err))
        }
    }
}

/// Pass an empty slice to indicate no peers.
///
async fn do_set_topology(
    vss_handle: &v1::v_s_s_handle::Client,
    peers: &[Link],
) -> Result<(), VssSyncError> {
    let mut req = vss_handle.set_topology_request();
    let req_builder = req.get();
    let mut peer_list_builder = req_builder.init_links(peers.len() as u32);

    for (i, peer) in peers.iter().enumerate() {
        let mut peer_builder = peer_list_builder.reborrow().get(i as u32);
        peer.write_to(&mut peer_builder);
    }

    let set_response_rdr =
        rpc_with_timeout("set-topology", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    let set_response_ok_or_err = set_response_rdr.get()?;

    match set_response_ok_or_err.get_res().unwrap().which().unwrap() {
        v1::ok_or_error::Which::Ok(_) => Ok(()),
        v1::ok_or_error::Which::Error(err_rdr) => {
            let api_err = ApiResponseError::try_from(err_rdr.unwrap())?;
            Err(VssSyncError::from(api_err))
        }
    }
}

/// Peers from policy may include hostnames. Here we run any hostnames through a
/// DNS lookup and create concrete `Link` objects with IP addresses. If any hostname fails
/// to resolve we just skip that peer and log an error.
async fn peers_to_links(peers: &[Peer]) -> Vec<Link> {
    let mut links = Vec::new();

    for peer in peers {
        match resolve_netaddr(&peer.remote_substrate).await {
            Ok(sock_addr) => {
                let sa: SockAddr = SockAddr {
                    addr: sock_addr.ip(),
                    port: sock_addr.port(),
                };
                //resolved.insert(&peer.link_id, sa);
                let link = Link {
                    link_id: peer.link_id.clone(),
                    role: LinkRole::Active, // only "active" support at the moment.
                    peer: sa,
                };
                links.push(link);
            }
            Err(e) => {
                error!(target: VSS, "failed to resolve address for peer {}: {}, skipping peer in topology", peer.link_id, e);
                continue;
            }
        }
    }

    links
}

async fn resolve_netaddr(naddr: &NetAddr) -> Result<SocketAddr, ResolverError> {
    match &naddr.host {
        NetworkHost::Ip(ip_addr) => Ok(SocketAddr::new(ip_addr.clone(), naddr.port)),
        NetworkHost::Hostname(hostname) => {
            let mut addrs = tokio::net::lookup_host((hostname.as_str(), naddr.port)).await?;
            addrs
                .next()
                .ok_or_else(|| ResolverError::NoAddresses(hostname.clone()))
        }
    }
}

#[derive(Debug)]
struct NoVerification;

// Implement the dangerous trait ServerCertVerifier NoVerification which will
// just always approve the connection
impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ML_DSA_44,
            SignatureScheme::ML_DSA_65,
            SignatureScheme::ML_DSA_87,
        ]
    }
}

// Create a dangerous connector - the verifier will always approve
// TODO decide if we want to use an actual certificate
fn tls_connect() -> TlsConnector {
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerification))
        .with_no_client_auth();

    TlsConnector::from(Arc::new(cfg))
}
