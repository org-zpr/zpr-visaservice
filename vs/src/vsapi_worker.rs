use chrono::prelude::{DateTime, Utc};
use ipnet::IpNet;
use openssl::rand::rand_bytes;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::*;
use tracing::{debug, error, info, warn};

use ::zpr::vsapi::v1 as vsapi;
use libeval::actor::Actor;
use libeval::attribute::{Attribute, key};
use zpr::vsapi_types::{ConnectRequest, Connection, PacketDesc, SockAddr, VisaOp};
use zpr::write_to::WriteTo;

use crate::assembly::Assembly;
use crate::config;
use crate::cparam;
use crate::cparam::CParam;
use crate::error::VSError;
use crate::event_mgr::VsEvent;
use crate::logging::targets::VSAPI;
use crate::visareq_worker::{VisaDecision, VisaRequestJob};

pub async fn launch_capnp(
    asm: Arc<Assembly>,
    listen: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(target: VSAPI, "VSAPI service listening on {} (capnp)", listen);
    let acceptor = tls_acceptor(listen)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;

    loop {
        // TODO: Figure out how to get tokio TLS in here.

        let (sock, addr) = listener.accept().await?;
        info!(target: VSAPI, "TCP connection from {}", addr);
        sock.set_nodelay(true)?;

        let tls = acceptor.accept(sock).await?;
        info!(target: VSAPI, "TLS connection");
        let (reader, writer) = tokio::io::split(tls);

        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            capnp::message::ReaderOptions::new(),
        );

        let vs_service: vsapi::visa_service::Client = capnp_rpc::new_client(VisaServiceImpl {
            asm: asm.clone(),
            remote: addr,
        });

        let rpc_system =
            capnp_rpc::RpcSystem::new(Box::new(network), Some(vs_service.clone().client));

        // TODO: spawn_local or spawn?
        tokio::task::spawn_local(async move {
            let err = rpc_system.await;
            err
        });
    }
}

pub async fn launch(asm: Arc<Assembly>, listen: SocketAddr) {
    match launch_capnp(asm.clone(), listen).await {
        Ok(()) => (),
        Err(e) => error!(target: VSAPI, "VSAPI capnp error: {}", e),
    };
}

// This function creates a certificate, and the clients will not require verification of the
// cert. In the future, we may actually want to share a cert between the VSAPI and VSS in VS/VSConn in Libnode2
fn tls_acceptor(listen: SocketAddr) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let self_signed_cert = rcgen::generate_simple_self_signed(vec![listen.to_string()])?;
    // Create self signed certificate that does not require client authentication
    let cert_der = self_signed_cert.cert.der();
    let key_der = self_signed_cert.key_pair.serialize_der();

    // Convert the cert into a format the
    let chain = vec![CertificateDer::from(cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;

    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

#[allow(dead_code)]
struct VisaServiceImpl {
    asm: Arc<Assembly>,
    remote: SocketAddr,
}

#[allow(dead_code)]
struct VSGateImpl {
    asm: Arc<Assembly>,
    remote: SocketAddr,
    remote_cn: String,
    req_zpr_addr: IpAddr,
    req_aaa_net: IpNet,

    // This is set in `challenge` call and read in the `authenticate` call.
    // Safe to use here since the capn proto rpc is confined to a single thread.
    challenge_data: Cell<[u8; 32]>,
}

#[allow(dead_code)]
struct VSHandleImpl {
    asm: Arc<Assembly>,
    node: Actor,
}

impl VSGateImpl {
    #[allow(dead_code)]
    fn new(
        asm: Arc<Assembly>,
        remote: SocketAddr,
        remote_cn: String,
        req_zpr_addr: IpAddr,
        req_aaa_net: IpNet,
    ) -> Self {
        VSGateImpl {
            asm,
            remote,
            remote_cn,
            challenge_data: Cell::new([0u8; 32]),
            req_zpr_addr,
            req_aaa_net,
        }
    }
}

impl VSHandleImpl {
    fn new(asm: Arc<Assembly>, node: Actor) -> Self {
        VSHandleImpl { asm, node }
    }

    // NOTES - (TO BE REMOVED EVENTUALLY)
    //
    // Create a visa-request "job" for the visa service and await
    // a reply on the response channel.
    //
    // The visa service will:
    //     - look up the actors make sure they exist, are not expired, etc.
    //     - may need to request new attributes
    //     - evaluate against policy
    //     - (if fails) we can reply fail.
    //     - (if ok) create the visa - mark it as PENDING.
    //     - reply over channel back to this function.
    //     - in this function we build the result and mark visa as INSTALLED.
    //
    // The idea is that another process can look for PENDING somehow were not installed....
    //
    //
    // Visa lifetime while we are traking them:
    //      (not in our DB) -> CREATED -> (after sent to a ndoe) INSTALLED
    //          -> (after admin revocation) REVOKED -> (after revoke is sent to nodes) (deleted from DB)
    //
    // A visa may need to go to many nodes.
    //
    // Maybe we keep a table for each node?
    // So when visa service creates a visa, it installs it as CREATED into all the node tables
    // where it needs to go.  Maybe a pointer to it?
    //
    //
    // MAIN VISA TABLE -> has list of all active visas created by VS.
    //                    The states are:
    //                         CREATED -> waiting to be installed on all relevant nodes.
    //                         INSTALLED -> installed on all relevant nodes.
    //                         REVOKED -> revoked, waiting to be deleted from all relevant nodes.
    //                         DEAD -> deleted from all nodes, can be removed from main table.
    //
    // Each node table has entries for visas (BY ID) with states:
    //                          PENDING -> waiting to be sent to node.
    //                          INSTALLED -> installed on node.
    //                          REVOKED -> revoked, waiting to be deleted from node.
    //

    // Helper to process a visa request and either return an API error or a visa decision.
    async fn do_visa_request(
        &self,
        args: vsapi::v_s_handle::VisaRequestParams,
        timeout: Duration,
    ) -> Result<VisaDecision, (vsapi::ErrorCode, String)> {
        let deadline = tokio::time::Instant::now() + timeout;

        let Some(requestor_ip) = self.node.get_zpr_addr() else {
            warn!(target: VSAPI, "visa_request called by node {:?} with no ZPR address assigned", self.node.get_cn());
            return Err((
                vsapi::ErrorCode::InvalidOperation,
                "node has no ZPR address assigned".to_string(),
            ));
        };

        let vreq = match args.get() {
            Ok(a) => match a.get_req() {
                Ok(r) => r,
                Err(e) => {
                    error!(target: VSAPI, "error getting visa request: {}", e);
                    return Err((
                        vsapi::ErrorCode::Internal,
                        "internal error getting visa request".to_string(),
                    ));
                }
            },
            Err(e) => {
                error!(target: VSAPI, "error getting visa request args: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    "internal error getting visa request args".to_string(),
                ));
            }
        };

        let cp_pdesc = match vreq.get_packet() {
            Ok(p) => p,
            Err(e) => {
                error!(target: VSAPI, "error getting packet description: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    "internal error getting packet description".to_string(),
                ));
            }
        };

        let previous_id = {
            let pid = vreq.get_previous_id();
            if pid > 0 { Some(pid) } else { None }
        };
        if previous_id.is_some() {
            warn!(target: VSAPI, "visa_request: supplied previous_id is ignored (TODO)");
        }

        let pdesc: PacketDesc = match cp_pdesc.try_into() {
            Ok(pd) => pd,
            Err(e) => {
                error!(target: VSAPI, "error parsing packet description: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    format!("invalid packet description: {}", e),
                ));
            }
        };

        let (job, response_rx) = VisaRequestJob::new(requestor_ip.clone(), pdesc);

        match tokio::time::timeout_at(deadline, self.asm.vreq_chan.send(job)).await {
            Ok(Ok(())) => (),
            Ok(Err(e)) => {
                error!(target: VSAPI, "error enqueuing visa request: {}", e);
                return Err((
                    vsapi::ErrorCode::Internal,
                    "internal error enqueuing visa request".to_string(),
                ));
            }
            Err(_) => {
                return Err((
                    vsapi::ErrorCode::Internal,
                    format!("timeout enqueuing visa request"),
                ));
            }
        };

        match tokio::time::timeout_at(deadline, response_rx).await {
            Ok(Ok(vr_result)) => match vr_result {
                Ok(vd) => return Ok(vd),
                Err(e) => {
                    return Err((
                        vsapi::ErrorCode::Internal,
                        format!("internal error processing visa request: {}", e),
                    ));
                }
            },
            Ok(Err(e)) => {
                return Err((
                    vsapi::ErrorCode::Internal,
                    format!("internal error receiving visa request response: {}", e),
                ));
            }
            Err(_) => {
                return Err((
                    vsapi::ErrorCode::Internal,
                    format!("timeout waiting for visa request response"),
                ));
            }
        }
    }
}

/// Helper to write an error into a capnp error builder with a retry of zero.
fn write_error(bldr: &mut vsapi::error::Builder, code: vsapi::ErrorCode, message: &str) {
    bldr.set_code(code);
    bldr.set_message(message);
    bldr.set_retry_in(0);
}

/// Convert a vsapi schema IpAddr into a rust ip address.
fn ipaddr_from_capnp(addr: vsapi::ip_addr::Reader) -> Result<std::net::IpAddr, capnp::Error> {
    match addr.which()? {
        vsapi::ip_addr::V4(ipv4) => {
            let octets = ipv4?;
            if octets.len() != 4 {
                return Err(capnp::Error::failed(
                    "invalid ipv4 address length".to_string(),
                ));
            }
            Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))
        }
        vsapi::ip_addr::V6(ipv6) => {
            let octets = ipv6?;
            if octets.len() != 16 {
                return Err(capnp::Error::failed(
                    "invalid ipv6 address length".to_string(),
                ));
            }
            let mut octets_copy = [0u8; 16];
            octets_copy.copy_from_slice(&octets);
            Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets_copy)))
        }
    }
}

impl VisaServiceImpl {
    /// Helper for the connect routine -- returns the two connect params we require: zpr_addr and aaa_prefix,
    /// or errors out.
    fn parse_my_connect_params(&self, params: &[CParam]) -> Result<(IpAddr, IpNet), VSError> {
        let node_zpr_addr: IpAddr = CParam::get_ipaddr(params, cparam::PARAM_ZPR_ADDR)?;
        let node_aaa_network_str = CParam::get_string(params, cparam::PARAM_AAA_PREFIX)?;
        let node_aaa_net: IpNet = match node_aaa_network_str.parse() {
            Ok(n) => n,
            Err(_e) => Err(VSError::ParamError(format!(
                "invalid ip prefix: {node_aaa_network_str}",
            )))?,
        };
        Ok((node_zpr_addr, node_aaa_net))
    }
}

impl vsapi::visa_service::Server for VisaServiceImpl {
    async fn connect(
        self: Rc<Self>,
        params: vsapi::visa_service::ConnectParams,
        mut results: vsapi::visa_service::ConnectResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "connect call from {}", self.remote);

        let vs_connect_request = params.get()?.get_req()?;

        let req_cn = vs_connect_request.get_cn()?.to_string()?;
        let req_type = vs_connect_request.get_ctype()?;

        let parsed_params = match CParam::from_connect_request(&vs_connect_request, 4) {
            Ok(p) => p,
            Err(e) => {
                let res_builder = results.get().init_resp();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal, // TODO: new error ParamError
                    format!("failed to parse connect params: {}", e).as_str(),
                );
                return Ok(());
            }
        };

        // We care about two params: zpr_addr and aaa_prefix.

        // TODO: In next version of vsapi the AAA_PREFIX is going away and will instead be handed to the
        // node by the visa service.
        let (node_zpr_addr, node_aaa_network) = match self.parse_my_connect_params(&parsed_params) {
            Ok((addr, cidr)) => (addr, cidr),
            Err(e) => {
                let res_builder = results.get().init_resp();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal, // TODO: new error ParamError
                    format!("{e}").as_str(),
                );
                return Ok(());
            }
        };

        info!(target: VSAPI, "node {} requests zpr addr {}", req_cn, node_zpr_addr);
        info!(target: VSAPI, "node {} requests aaa network {}", req_cn, node_aaa_network);

        match req_type {
            vsapi::VSConnT::Reset => {}
            vsapi::VSConnT::Reconnect => {
                let res_builder = results.get().init_resp();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::AuthRequired,
                    "reconnect not supported",
                );
                return Ok(());
            }
        }

        let mut res_builder = results.get().init_resp();

        let vs_gate: vsapi::v_s_gate::Client = capnp_rpc::new_client(VSGateImpl::new(
            self.asm.clone(),
            self.remote,
            req_cn,
            node_zpr_addr,
            node_aaa_network,
        ));

        //res_builder.reborrow().set_ok(vs_gate)?;
        res_builder.set_ok(vs_gate)?;

        Ok(())
    }
}

impl vsapi::v_s_gate::Server for VSGateImpl {
    async fn challenge(
        self: Rc<Self>,
        _params: vsapi::v_s_gate::ChallengeParams,
        mut results: vsapi::v_s_gate::ChallengeResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "challenge call from {} as {}", self.remote, self.remote_cn);
        let mut res_builder = results.get().init_challenge();
        res_builder.set_alg(vsapi::ChallengeAlg::RsaSha256Pkcs1v15);
        let mut challenge_data = [0u8; 32];
        rand_bytes(&mut challenge_data).unwrap();
        res_builder.set_bytes(&challenge_data);
        self.challenge_data.set(challenge_data);
        Ok(())
    }

    /// Authenticate VSAPI call is also the "authorize_connect" call for a node.
    async fn authenticate(
        self: Rc<Self>,
        params: vsapi::v_s_gate::AuthenticateParams,
        mut results: vsapi::v_s_gate::AuthenticateResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "authenticate from {} as {}", self.remote, self.remote_cn);
        let cresp = params.get()?.get_cresp()?; // has challenge (bytes), timestamp (uint64), bytes (bytes)
        let mut res_builder = results.get().init_res();
        let challenge_presented = cresp.get_challenge()?;

        // We must have sent challenge data ... meaning it cannot all be zeros.
        if challenge_presented.iter().all(|&b| b == 0) {
            warn!(target: VSAPI, "all zeros challenge presented from {}, authenticate fails", self.remote_cn);
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::InvalidOperation, // TODO: New code 'AuthError'
                "invalid challenge",
            );
            return Ok(());
        }

        // Must match the challenge we sent.
        if challenge_presented != &self.challenge_data.get() {
            warn!(target: VSAPI, "invalid challenge from {}, authenticate fails", self.remote_cn);
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::InvalidOperation, // TODO: New code 'AuthError'
                "challenge mismatch",
            );
            return Ok(());
        }

        // Challenge is one time use - so we set our memory of it to zeros.
        self.challenge_data.set([0u8; 32]);

        // Time must be within acceptable range.
        let unix_ts = cresp.get_timestamp();
        let now = SystemTime::now();
        let my_unix_ts = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        if my_unix_ts.abs_diff(unix_ts) > config::MAX_CLOCK_SKEW_SECS {
            warn!(target: VSAPI, "excess clock skew from {}, authenticate fails", self.remote_cn);
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::OutOfSync,
                "excess clock skew",
            );
            return Ok(());
        }

        let challenge_response = cresp.get_bytes()?;

        // Perform the authentication
        //
        let mut node_actor = match self
            .asm
            .cc
            .authenticate_node(
                self.asm.clone(),
                challenge_presented,
                unix_ts,
                &self.remote_cn,
                challenge_response,
                self.remote,
                self.req_zpr_addr,
            )
            .await
        {
            Ok(n_actor) => n_actor,
            Err(VSError::AuthenticationFailed(reason)) => {
                warn!(target: VSAPI, "authentication failed for {}: {}", self.remote_cn, reason);
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::AuthError,
                    format!("authentication failed: {reason}").as_str(),
                );
                return Ok(());
            }
            Err(e) => {
                error!(target: VSAPI, "internal error during authentication for {}: {}", self.remote_cn, e);
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "internal error during authentication",
                );
                return Ok(());
            }
        };

        // Sanity check - every node has a CN and a ZPR address.
        // If this fails it means our authentication code is broken.
        let node_cn = match node_actor.get_cn() {
            Some(cn) => cn.to_owned(),
            None => {
                error!(target: VSAPI, "auth subsystem failed to set a CN on an authenticated node");
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "assertion failed (CN)",
                );
                return Ok(());
            }
        };
        let node_zpr_addr = match node_actor.get_zpr_addr() {
            Some(addr) => addr.clone(),
            None => {
                error!(target: VSAPI, "auth subsystem failed to set a ZPR address on an authenticated node");
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "assertion failed (ADDR)",
                );
                return Ok(());
            }
        };

        info!(
            target: VSAPI,
            "successfully authenticated node {:?} from {:?} and assigned ip {:?}",
            &node_cn, self.remote, &node_zpr_addr
        );

        // Ok, we have verified the credentials and checked with policy. Time to
        // update our state and return success.

        // TODO: aaa_prefix is going to be set by visa service.
        node_actor
            .add_attribute(Attribute::builder(key::AAA_NET).value(self.req_aaa_net.to_string()))
            .unwrap();

        // TODO: The policy may have changed since started the authentication. Once we add the node
        // it is part of the ZPRnet.  The add_node should check the visa vinst used to grant access
        // and we should make sure we do not allow add_node and update_policy to run concurrently.
        // If add_node runs first, then update policy can catch the issue.  If update_policy runs
        // first, then add_node will see the new version and should not allow the node to be added.

        // Note that the node may have services on it in addition to its node-ness.

        // Since this is a new node and we do not yet support reconnects, make sure visa
        // table is clean for this node.
        if let Err(e) = self.asm.visa_mgr.clear_node_state(&node_zpr_addr).await {
            warn!(target: VSAPI, "failed to clear node state for {:?}: {}", &node_cn, e);
        }

        if let Err(e) = self.asm.actor_mgr.add_node(&node_actor).await {
            error!(target: VSAPI, "failed to add authenticated node {:?} to actor db: {}", &node_cn, e);
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::Internal,
                "state update failed",
            );
            return Ok(());
        }

        let evt = VsEvent::ActorJoins(node_zpr_addr);
        if let Err(e) = self.asm.event_mgr.record_event(evt).await {
            warn!(target: VSAPI, "failed to record actor joins event for node {:?}: {}", &node_cn, e);
        }

        let vs_handle: vsapi::v_s_handle::Client =
            capnp_rpc::new_client(VSHandleImpl::new(self.asm.clone(), node_actor));
        res_builder.set_ok(vs_handle)?;

        Ok(())
    }
}

impl vsapi::v_s_handle::Server for VSHandleImpl {
    /// Node should call this after it has authenticated itself and it has installed its
    /// ZPR address into its tables.
    ///
    /// The VS must generate a visa for VISA->VSS communications and hand it back to
    /// the node with this call.  Any pending visas for the node are handed back with this.
    ///
    async fn register_vss(
        self: Rc<Self>,
        params: vsapi::v_s_handle::RegisterVssParams,
        mut res: vsapi::v_s_handle::RegisterVssResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "register_vss from {:?}", self.node.get_cn());
        let saddr_rdr = params.get()?.get_addr()?;

        let node_zpr_addr = self.node.get_zpr_addr().unwrap();

        let vss_sockaddr: SockAddr = match SockAddr::try_from(saddr_rdr) {
            Ok(addr) => addr,
            Err(e) => {
                error!(target: VSAPI, "failed to convert addr arg to SockAddr: {}", e);
                let res_builder = res.get().init_res();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::ParamError,
                    "invalid sockaddr",
                );
                return Ok(());
            }
        };

        // The socket addr address must match node address I think.
        if vss_sockaddr.addr != *node_zpr_addr {
            error!(target: VSAPI, "VSS socket address '{}' does not match node address '{}' for {:?}", vss_sockaddr.addr, node_zpr_addr, self.node.get_cn());
            let res_builder = res.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::ParamError,
                "VSS socket address does not match node address",
            );
            return Ok(());
        }

        let saddr: SocketAddr = vss_sockaddr.into();
        let amgr_asm = self.asm.clone();

        let initial_visas = match self
            .asm
            .visa_mgr
            .initial_visas_for_node(amgr_asm, node_zpr_addr, &saddr)
            .await
        {
            Ok(visas) => visas,
            Err(e) => {
                error!(target: VSAPI, "failed to initialize node VSS for {:?}: {}", self.node.get_cn(), e);
                let res_builder = res.get().init_res();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "failed to initialize node VSS",
                );
                return Ok(());
            }
        };

        let res_builder = res.get().init_res();
        let mut ok_builder = res_builder.initn_ok(initial_visas.len() as u32);

        for (i, visa) in initial_visas.iter().enumerate() {
            let mut vop_builder = ok_builder.reborrow().get(i as u32);

            let vop = VisaOp::Grant(visa.clone());
            vop.write_to(&mut vop_builder);
        }

        // Now assume that our reply will make it to the node and mark the visas as installed.
        //
        // The node must assume that if it gets an error trying to call register_vss that
        // there may be visas it is missing.  Since we don't have a way for the node to
        // ask for its "installed" visas, for now node should call register_vss again.
        //
        // TODO: Improve vsapi by adding a way for node to request its installed visas.
        // https://github.com/org-zpr/zpr-visaservice/issues/108

        for visa in &initial_visas {
            if let Err(e) = self
                .asm
                .visa_mgr
                .visa_installed(visa.issuer_id, node_zpr_addr)
                .await
            {
                warn!(target: VSAPI, "failed to mark visa {} as installed on {:?}: {}", visa.issuer_id, self.node.get_cn(), e);
            }
        }

        // Finally, update DB with node vss
        self.asm
            .actor_mgr
            .set_node_vss(&self.node.get_zpr_addr().unwrap(), &saddr)
            .await
            .unwrap_or_else(|e| {
                error!(target: VSAPI, "failed to set VSS for node {:?}: {}", self.node.get_cn(), e);
            });

        // As we return we kick off the vss worker for this node which will send list of services.
        // but will not work until visas are installed... So start it with small delay.
        if let Err(e) =
            self.asm
                .vss_mgr
                .start_vss_worker(self.asm.clone(), &saddr, config::VSS_START_DELAY)
        {
            warn!(target: VSAPI, "failed to start VSS worker for node {:?}: {}", self.node.get_cn(), e);
            // TODO: how to recover here?
        }

        Ok(())
    }

    // When an adapter connects to ta node, a node ends up making a call here to authorize
    // the connection.  If successful the VS returns a ZPR address for the adapter, and an
    // expiration time.
    //
    // The ConnectRequest arg is populated as follows:
    //       blobs: list of 1 (for now) 'AuthBlob'
    //       claims: may include 'zpr.addr' if a specific address is requested, must include 'zpr.adapter.cn' to match blob cn.
    //       substrateAddr: adapter substrate address
    //       dockinterface: 0
    //
    // There are just two ways that an adapter can authenticated and that is reflected in
    // the AuthBlob presented.
    //
    // (1) Adapter uses an RSA key that is shared with policy -- looked up by the adapter CN.
    //
    //     Note that the node has already verified that the CN in the blob matches the CN
    //     presented over the link by the adapter.
    //
    //     The AuthBlob is a ZPRSelfSignedBlob
    //       {
    //         alg: ChallengeAlg::RsaSha256Pkcs1v15
    //         challenge: <bytes> - The nodes challend to the adapter. Just opaque bytes to to the visa service.
    //         cn: adapter CN value
    //         timestamp: unix timestamp, seconds
    //         signature: RSA SHA256 PKCS1v15 signature using adapter private key over (ts + cn + challenge)
    //                    time is big-endian u64.
    //       }
    //
    //     To verify the blob, the visa service looks up the public key in policy by CN,
    //     and then verifies the signature.
    //
    //
    // (2) It can present a token from an authentication server.
    //
    //     The AuthBlob is a AuthCodeBlob
    //       {
    //         asaAddr: IpAddr of the auth service
    //         code: <string>
    //         pkce: <string>
    //         clientId: <string>
    //       }
    //
    //     All this is used in the oauth flow between visa service and the auth server to verify
    //     the adapter identity.
    //
    async fn authorize_connect(
        self: Rc<Self>,
        params: vsapi::v_s_handle::AuthorizeConnectParams,
        mut results: vsapi::v_s_handle::AuthorizeConnectResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "authorize_connect from {:?}", self.node.get_cn());

        let cr_rdr = params.get()?.get_req()?;
        let creq = ConnectRequest::try_from(cr_rdr).map_err(|e| {
            capnp::Error::failed(format!("failed to parse ConnectionRequest: {}", e))
        })?;

        let connect_via = self.node.get_zpr_addr().unwrap();

        let actor = match self
            .asm
            .cc
            .authenticate_adapter(self.asm.clone(), creq, connect_via)
            .await
        {
            Ok(actor) => actor,
            Err(e) => {
                warn!(target: VSAPI, "adapter connection authorization failed for node {:?}: {}", connect_via, e);
                let mut err_builder = results.get().init_resp().init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::AuthError,
                    format!("adapter authorization failed: {}", e).as_str(),
                );
                return Ok(());
            }
        };

        let actor_addr = actor.get_zpr_addr().unwrap().clone(); // MUST have an addr by now.

        // Have an actor. Will have a ZPR address at this point.
        if let Err(e) = self
            .asm
            .actor_mgr
            .add_adapter_via_node(&actor, &connect_via)
            .await
        {
            error!(target: VSAPI, "failed to add authenticated adapter {:?} to actor db: {}", actor.get_cn(), e);

            if let Err(e) = self.asm.net_mgr.release_zpr_addr(actor_addr).await {
                warn!(target: VSAPI, "failed to release adapter address {}: {}", actor_addr, e);
            }

            let mut err_builder = results.get().init_resp().init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::Internal,
                "state update failed",
            );
            return Ok(());
        }

        let addr_attr = actor.get_attribute(key::ZPR_ADDR).unwrap();
        {
            let expires_utc: DateTime<Utc> = addr_attr.get_expires().into();
            info!(
                target: VSAPI,
                "successfully authorized adapter {:?} with address {} (expires {})",
                actor.get_cn(),
                actor_addr,
                expires_utc.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            );
        }
        let zpr_con = Connection::new(actor_addr, addr_attr.get_expires());
        let mut resp_builder = results.get().init_resp().init_ok();
        zpr_con.write_to(&mut resp_builder);

        let evt = VsEvent::ActorJoins(actor_addr);
        if let Err(e) = self.asm.event_mgr.record_event(evt).await {
            warn!(target: VSAPI, "failed to record actor joins event for adapter {:?}: {}", actor.get_cn(), e);
        }

        Ok(())
    }

    async fn reauthorize(
        self: Rc<Self>,
        _: vsapi::v_s_handle::ReauthorizeParams,
        _: vsapi::v_s_handle::ReauthorizeResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "reauthorize from {:?}", self.node.get_cn());
        Err(capnp::Error::unimplemented(
            "method v_s_handle::Server::reauthorize not implemented".to_string(),
        ))
    }

    async fn notify_disconnect(
        self: Rc<Self>,
        req: vsapi::v_s_handle::NotifyDisconnectParams,
        mut resp: vsapi::v_s_handle::NotifyDisconnectResults,
    ) -> Result<(), capnp::Error> {
        let dnotice = req.get()?.get_req()?;

        // If no ZPR address is specified that means that the node itself is disconnecting.
        let maybe_zpr_addr = if dnotice.has_zpr_addr() {
            let zpr_ipaddr = dnotice.get_zpr_addr()?;
            Some(ipaddr_from_capnp(zpr_ipaddr)?)
        } else {
            // populate with the actor ZPR addr.
            self.node.get_zpr_addr().cloned()
        };

        // I believe we need a ZPR address here otherwise this is just a NOP.
        if maybe_zpr_addr.is_none() {
            warn!(target: VSAPI, "notify_disconnect but no zpr address passed or derivable from actor {:?}", self.node.get_cn());
            let res_builder = resp.get().init_res();
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::InvalidOperation,
                "disconnect requires zpr address",
            );
            return Ok(());
        }
        let zpr_addr = maybe_zpr_addr.unwrap();

        let reason = dnotice.get_reason_code()?;
        debug!(
            target: VSAPI,
            "disconnect call from node {:?} for {} with reason {:?}",
            self.node.get_cn(), zpr_addr, reason
        );

        let evt = VsEvent::ActorLeaves(zpr_addr, reason);
        if let Err(e) = self.asm.event_mgr.record_event(evt).await {
            warn!(target: VSAPI, "failed to record actor leaves event for {}: {}", zpr_addr, e);
        }
        let mut res_builder = resp.get().init_res();
        res_builder.set_ok(());
        Ok(())
    }

    async fn visa_request(
        self: Rc<Self>,
        args: vsapi::v_s_handle::VisaRequestParams,
        mut response: vsapi::v_s_handle::VisaRequestResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "visa_request from {:?}", self.node.get_cn());

        // A node must have an address.
        let requestor_addr = self
            .node
            .get_zpr_addr()
            .expect("programming error - node must have an address");

        match self
            .do_visa_request(args, config::DEFAULT_VISA_REQ_TIMEOUT)
            .await
        {
            Ok(decision) => match decision {
                VisaDecision::Allow(visa) => {
                    let res_builder = response.get().init_resp();
                    let mut visa_bldr = res_builder.init_allow();
                    visa.write_to(&mut visa_bldr);

                    // Set visa as installed in our state
                    if let Err(e) = self
                        .asm
                        .visa_mgr
                        .visa_installed(visa.issuer_id, requestor_addr)
                        .await
                    {
                        error!(target: VSAPI, "failed to update visa {} as installed on {}: {}", visa.issuer_id, requestor_addr, e);
                    }
                }
                VisaDecision::Deny(denial_reason) => {
                    let mut res_builder = response.get().init_resp();
                    res_builder.set_deny(denial_reason.into());
                }
            },

            Err((code, msg)) => {
                error!(target: VSAPI, "internal error ({code:?})processing visa_request: {msg}");
                let res_builder = response.get().init_resp();
                let mut err_builder = res_builder.init_error();
                write_error(&mut err_builder, code, &msg);
            }
        }
        return Ok(());
    }

    async fn ping(
        self: Rc<Self>,
        _req: vsapi::v_s_handle::PingParams,
        mut results: vsapi::v_s_handle::PingResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "ping from {:?}", self.node.get_cn());
        let mut res_builder = results.get().init_res();
        res_builder.set_ok(());
        Ok(())
    }
}
