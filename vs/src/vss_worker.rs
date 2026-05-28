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
    ApiResponseError, Link, LinkRole, Param, ServiceDescriptor, SockAddr, Visa, pname,
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

#[derive(Debug, Default)]
struct VssState {
    last_configure: Option<Instant>,
    services_state: AgedState,
    topology_state: AgedState,
}

impl VssState {
    fn needs_configure(&self) -> bool {
        self.last_configure.is_none()
    }

    /// Indicates that the initial configuration call was performed.
    fn mark_configured(&mut self) {
        self.last_configure = Some(Instant::now());
    }

    fn needs_set_services(&self) -> bool {
        self.services_state.needs_sync()
    }

    fn mark_services_updated(&mut self) {
        self.services_state.last_update = Instant::now();
    }

    /// Indicates we have sent the services list across.
    fn mark_services_syncd(&mut self) {
        self.services_state.mark_syncd();
    }

    /// TODO: This is not yet tracking policy changes. So only returns TRUE first time it is created.
    fn needs_set_topology(&self) -> bool {
        self.topology_state.needs_sync()
    }

    /// If topology effecting this node has been updated, indicate that here.
    /// TODO: Not used yet.
    #[allow(dead_code)]
    fn mark_topology_updated(&mut self) {
        self.topology_state.last_update = Instant::now();
    }

    /// Indicates we have sent the topology information across.
    fn mark_topology_syncd(&mut self) {
        self.topology_state.mark_syncd();
    }
}

#[derive(Debug)]
struct AgedState {
    last_update: Instant,
    last_sync: Option<Instant>,
}

impl AgedState {
    fn needs_sync(&self) -> bool {
        self.last_sync.is_none() || self.last_sync.as_ref().unwrap() < &self.last_update
    }

    fn mark_syncd(&mut self) {
        self.last_sync = Some(Instant::now());
    }
}

impl Default for AgedState {
    fn default() -> Self {
        Self {
            last_update: Instant::now(),
            last_sync: None,
        }
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

    let vss_handle = match vss_connect(node_addr).await {
        Ok(h) => h,
        Err(e) => {
            error!(target: VSS, "failed to connect to VSS at {}: {}", node_addr, e);
            asm.counters.incr(CounterType::VssErrors);
            return;
        }
    };

    info!(target: VSS, "now connected to VSS at {}", node_addr);
    let mut state = VssState::default();
    do_housekeeping(&mut state, &asm, &node_addr.ip(), &vss_handle).await;

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
                        VssCmd::PushVisas(visas, resp_tx) => {
                            if let Err(e) = resp_tx.send(vss_do_push_visas(&vss_handle, &visas).await) {
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
                            state.mark_services_updated();
                            if let Err(e) = resp_tx.send(vss_do_set_services(&vss_handle, services).await) {
                                error!(target: VSS, "failed to send response for set-services command: {:?}", e);
                                asm.counters.incr(CounterType::VssErrors);
                            }
                        }
                        VssCmd::Configure(params, resp_tx) => {
                            if let Err(e) = resp_tx.send(vss_do_configure(&vss_handle, params).await) {
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

/// Perform TCP connect, TLS handshake, Cap'n Proto RPC bootstrap, and the initial
/// connect RPC, returning a ready-to-use VSS handle client.
async fn vss_connect(node_addr: SocketAddr) -> Result<v1::v_s_s_handle::Client, VssSyncError> {
    let sock = tokio::net::TcpStream::connect(node_addr)
        .await
        .map_err(|e| VssSyncError::Internal(format!("TCP connect: {e}")))?;

    let tls = tls_connect()
        .connect(node_addr.ip().into(), sock)
        .await
        .map_err(|e| VssSyncError::Internal(format!("TLS handshake: {e}")))?;

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
        rpc_with_timeout("connect", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    let handle_result_ok_or_error = handle_result_rdr.get()?.get_resp()?;
    match handle_result_ok_or_error.which().unwrap() {
        v1::result::Which::Ok(vss_handle_obj) => Ok(vss_handle_obj.unwrap()),
        v1::result::Which::Error(err_obj) => {
            let err_obj = err_obj.unwrap();
            Err(VssSyncError::Internal(format!(
                "VSS rejected connect: code={:?} msg={:?}",
                err_obj.get_code(),
                err_obj.get_message(),
            )))
        }
    }
}

async fn do_housekeeping(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    // Currently these three items are all onoly part of intiial VSS connection.
    // Once they are sent, they are not sent again.
    if state.needs_configure() {
        send_configure(state, asm, node_addr, vss_handle).await;
    }
    if state.needs_set_services() {
        send_auth_services(state, asm, node_addr, vss_handle).await;
    }
    if state.needs_set_topology() {
        send_topology(state, asm, node_addr, vss_handle).await;
    }

    send_pending_visas(asm, node_addr, vss_handle).await;

    // TODO: Check for pending visa revocations.
    // TODO: Check for pending authentication revocations.
}

/// If there are pending visas for this node, use VSS api to send them over.
/// Update DB state if we are successful.
async fn send_pending_visas(
    asm: &Assembly,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    match asm.visa_mgr.get_pending_visas_for_node(node_addr).await {
        Ok(pending_visas) => {
            let mut actualized = Vec::new();
            for visa in pending_visas {
                let issuer_id = visa.issuer_id;
                match asm
                    .visa_mgr
                    .actualize_visa_for_target_node(visa, node_addr)
                    .await
                {
                    Ok(a_visa) => actualized.push(a_visa),
                    Err(e) => {
                        error!(target: VSS, "failed to actualize pending visa {issuer_id} for node {}: {}", node_addr, e);
                    }
                }
            }
            if !actualized.is_empty() {
                match vss_do_push_visas(vss_handle, &actualized).await {
                    Ok(processed) => {
                        // Update our state for the processed visas.
                        // TODO: Need to consider that housekeeping will run frequently, possibly bombarding
                        // nodes that for some reason are not accepting visas. Not sure correct solution yet.
                        for (i, pushed) in actualized.iter().enumerate() {
                            if i >= processed {
                                break;
                            }
                            if let Err(e) = asm
                                .visa_mgr
                                .visa_installed(pushed.issuer_id, &node_addr)
                                .await
                            {
                                // TODO: Means it will be attempt to be installed next housekeeping run.
                                warn!(target: VSS,
                                    "error marking visa {} as installed for node {node_addr}: {e}", pushed.issuer_id
                                );
                            }
                        }

                        debug!(target: VSS, "successfully pushed {} pending visas to node {}", actualized.len(), node_addr);
                    }
                    Err(e) => {
                        error!(target: VSS, "failed to push {} pending visas to node {}: {}", actualized.len(), node_addr, e);
                        return;
                    }
                }
            }
        }
        Err(e) => {
            warn!(target: VSS, "failed to get pending visas for node {}: {}", node_addr, e);
        }
    }
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
    match vss_do_configure(vss_handle, params).await {
        Ok(_) => {
            debug!(target: VSS, "{node_addr} configured successfully");
            state.mark_configured();
        }
        Err(e) => {
            warn!(target: VSS, "failed to configure VSS at {node_addr}: {e}");
            asm.counters.incr(CounterType::VssErrors);
        }
    }
}

async fn send_auth_services(
    state: &mut VssState,
    asm: &Arc<Assembly>,
    node_addr: &IpAddr,
    vss_handle: &v1::v_s_s_handle::Client,
) {
    match asm.actor_mgr.get_auth_services_list(asm.clone()).await {
        Ok(services) => {
            debug!(target: VSS, "sending initial auth services list to VSS at {}", node_addr);
            if let Err(e) = vss_do_set_services(&vss_handle, services).await {
                error!(target: VSS, "failed to send initial auth services list to VSS at {}: {}", node_addr, e);
                asm.counters.incr(CounterType::VssErrors);
            } else {
                debug!(target: VSS, "initial auth services list sent to VSS at {}", node_addr);
                state.mark_services_syncd();
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
    if let Err(e) = vss_do_set_topology(vss_handle, &links).await {
        error!(target: VSS, "failed to send initial topology to VSS at {}: {}", node_addr, e);
        asm.counters.incr(CounterType::VssErrors);
    } else {
        debug!(target: VSS, "initial topology sent to VSS at {}", node_addr);
        state.mark_topology_syncd();
    }
}

/// Peers from policy may include hostnames. Here we run any hostnames through a
/// DNS lookup and create concrete `Link` objects with IP addresses. If any hostname fails
/// to resolve we just skip that peer and log an error.
async fn peers_to_links(peers: &[Peer]) -> Vec<Link> {
    // Attempt to parallelize the DNS lookups.
    let futs = peers
        .iter()
        .map(|peer| async move { (peer, resolve_netaddr(&peer.remote_substrate).await) });

    futures::future::join_all(futs)
        .await
        .into_iter()
        .filter_map(|(peer, result)| match result {
            Ok(sock_addr) => Some(Link {
                link_id: peer.link_id.clone(),
                role: LinkRole::Active, // only "active" support at the moment.
                peer: SockAddr {
                    addr: sock_addr.ip(),
                    port: sock_addr.port(),
                },
            }),
            Err(e) => {
                error!(target: VSS, "failed to resolve address for peer {}: {}, skipping peer in topology", peer.link_id, e);
                None
            }
        })
        .collect()
}

/// If the passed `NetAddr` contains a hostname, perform a DNS lookup to resolve it to an IP address.
/// Otherwise this quickly just returns a SocketAddr.
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

/// Map a Cap'n Proto ok-or-error reader to a `Result`, converting API errors.
fn check_ok_or_error(r: v1::ok_or_error::Reader<'_>) -> Result<(), VssSyncError> {
    match r.which().unwrap() {
        v1::ok_or_error::Which::Ok(_) => Ok(()),
        v1::ok_or_error::Which::Error(err_rdr) => {
            let api_err = ApiResponseError::try_from(err_rdr.unwrap())?;
            Err(VssSyncError::from(api_err))
        }
    }
}

/// Performt he VSS push_visas call, returns the number of visas positively ack'd by node.
/// Treats zero visas processed as an error.
async fn vss_do_push_visas(
    vss_handle: &v1::v_s_s_handle::Client,
    visas: &[Visa],
) -> Result<usize, VssSyncError> {
    let mut req = vss_handle.push_visa_op_request();
    let req_builder = req.get();
    let mut ops_list_builder = req_builder.init_ops(visas.len() as u32);

    // A VisaOp is either a Grant or a Revoke; these are all GRANTs here.
    for (i, visa) in visas.iter().enumerate() {
        let op_builder = ops_list_builder.reborrow().get(i as u32);
        let mut grant_builder = op_builder.init_grant();
        visa.write_to(&mut grant_builder);
    }

    let push_response_rdr =
        rpc_with_timeout("push-visas", DEFAULT_RPC_TIMEOUT, req.send().promise).await?;

    // Response is an Ack struct (TODO: Add this to the vsapi types in zpr-common)
    let ack_response = push_response_rdr.get()?.get_ack()?;
    if ack_response.get_ok() {
        // At least one visa was processed. In this case we return the number processed and
        // log the error (if any).
        let processed = ack_response.get_processed() as usize;
        if processed < visas.len() {
            let err_rdr = ack_response.get_error()?;
            let err_obj = ApiResponseError::try_from(err_rdr)?;
            error!(target: VSS, "push-visas partially succeeded: {} of {} processed, error code={:?} msg={}",
            processed, visas.len(), err_obj.code, err_obj.message);
        }
        return Ok(processed);
    } else {
        // No visas were processed.  Return error or zero ?? Not sure.
        let err_rdr = ack_response.get_error()?;
        let err_obj = ApiResponseError::try_from(err_rdr)?;
        return Err(err_obj.into());
    }
}

async fn vss_do_set_services(
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
    check_ok_or_error(set_response_ok_or_err.get_res().unwrap())
}

async fn vss_do_configure(
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
    check_ok_or_error(configure_response_ok_or_err.get_res().unwrap())
}

/// Pass an empty slice to indicate no peers.
///
async fn vss_do_set_topology(
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
    check_ok_or_error(set_response_ok_or_err.get_res().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libeval::policy::Peer;
    use std::net::IpAddr;
    use zpr::policy_types::{NetAddr, NetworkHost};
    use zpr::vsapi_types::LinkRole;

    fn ip_peer(link_id: &str, ip: IpAddr, port: u16) -> Peer {
        Peer {
            link_id: link_id.to_string(),
            remote_zpr_addr: "fd5a:5052::1".parse().unwrap(),
            remote_substrate: NetAddr {
                host: NetworkHost::Ip(ip),
                port,
            },
        }
    }

    /// Empty peer slice produces an empty link list.
    #[tokio::test]
    async fn test_peers_to_links_empty() {
        let links = peers_to_links(&[]).await;
        assert!(links.is_empty());
    }

    /// A single IP peer maps to a single Link with the correct fields.
    #[tokio::test]
    async fn test_peers_to_links_single_ip() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let peer = ip_peer("link-a", ip, 4000);

        let links = peers_to_links(&[peer]).await;

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_id, "link-a");
        assert_eq!(links[0].role, LinkRole::Active);
        assert_eq!(links[0].peer.addr, ip);
        assert_eq!(links[0].peer.port, 4000);
    }

    /// Multiple IP peers produce one Link each, in the same order.
    #[tokio::test]
    async fn test_peers_to_links_multiple_ips() {
        let ip_a: IpAddr = "192.0.2.1".parse().unwrap();
        let ip_b: IpAddr = "192.0.2.2".parse().unwrap();
        let peers = [ip_peer("link-a", ip_a, 4000), ip_peer("link-b", ip_b, 5000)];

        let links = peers_to_links(&peers).await;

        assert_eq!(links.len(), 2);
        assert_eq!(links[0].link_id, "link-a");
        assert_eq!(links[0].peer.addr, ip_a);
        assert_eq!(links[1].link_id, "link-b");
        assert_eq!(links[1].peer.addr, ip_b);
    }

    /// A peer with an unresolvable hostname is silently dropped; valid IP peers survive.
    #[tokio::test]
    async fn test_peers_to_links_bad_hostname_skipped() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let good = ip_peer("link-good", ip, 4000);
        let bad = Peer {
            link_id: "link-bad".to_string(),
            remote_zpr_addr: "fd5a:5052::2".parse().unwrap(),
            remote_substrate: NetAddr {
                host: NetworkHost::Hostname("this.hostname.does.not.exist.invalid".to_string()),
                port: 4000,
            },
        };

        let links = peers_to_links(&[good, bad]).await;

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_id, "link-good");
    }
}
