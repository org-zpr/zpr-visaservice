use ::zpr::vsapi::v1 as vsapi;

use ipnet::IpNet;
use openssl::rand::rand_bytes;
use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::compat::*;
use tracing::{debug, error, info, warn};

use libeval::actor::Actor;

use crate::assembly::Assembly;
use crate::error::VSError;
use crate::logging::targets::VSAPI;
use crate::zpr;

const PARAM_ZPR_ADDR: &str = "zpr_addr";
const PARAM_AAA_PREFIX: &str = "aaa_prefix";

pub async fn launch_capnp(
    asm: Arc<Assembly>,
    listen: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(target: VSAPI, "VSAPI service listening on {} (capnp)", listen);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    loop {
        // TODO: Figure out how to get tokio TLS in here.

        let (sock, addr) = listener.accept().await?;

        info!(target: VSAPI, "connection from {}", addr);

        sock.set_nodelay(true)?;

        let (reader, writer) = sock.into_split();

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
        let node_zpr_addr: IpAddr = CParam::get_ipaddr(params, PARAM_ZPR_ADDR)?;
        let node_aaa_network_str = CParam::get_string(params, PARAM_AAA_PREFIX)?;
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
        if my_unix_ts.abs_diff(unix_ts) > zpr::MAX_CLOCK_SKEW_SECS {
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
        let node_actor = match self
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
                self.req_aaa_net,
            )
            .await
        {
            Ok(node_id) => node_id,
            Err(VSError::AuthenticationFailed(reason)) => {
                warn!(target: VSAPI, "authentication failed for {}: {}", self.remote_cn, reason);
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::InvalidOperation, // TODO: New code 'AuthError'
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
        if node_actor.get_cn().is_none() {
            error!(target: VSAPI, "auth subsystem failed to set a CN on an authenticated node");
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::Internal,
                "assertion failed (CN)",
            );
            return Ok(());
        }
        if node_actor.get_zpr_addr().is_none() {
            error!(target: VSAPI, "auth subsystem failed to set a ZPR address on an authenticated node");
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::Internal,
                "assertion failed (ADDR)",
            );
            return Ok(());
        }

        info!(
            target: VSAPI,
            "successfully authenticated node {:?} from {:?} and assigned ip {:?}",
            node_actor.get_cn(), self.remote, node_actor.get_zpr_addr()
        );

        // Ok, we have verified the credentials and checked with policy. Time to
        // update our state and return success.

        // TODO: The policy may have changed since started the authentication. Once we add the node
        // it is part of the ZPRnet.  The add_node should check the visa vinst used to grant access
        // and we should make sure we do not allow add_node and update_policy to run concurrently.
        // If add_node runs first, then update policy can catch the issue.  If update_policy runs
        // first, then add_node will see the new version and should not allow the node to be added.

        // Note that the node may have services on it in addition to its node-ness.

        // The node has a built in temporary(?) visa for communicating with the VS.
        // The VS will create a "real" one and queue it to be sent to the node once
        // it registers its VSS.

        if let Err(e) = self.asm.actor_db.add_node(node_actor.clone()) {
            error!(target: VSAPI, "failed to add authenticated node {:?} to actor db: {}", node_actor.get_cn(), e);
            let mut err_builder = res_builder.init_error();
            write_error(
                &mut err_builder,
                vsapi::ErrorCode::Internal,
                "state update failed",
            );
            return Ok(());
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
    /// PENDING (TODO) - Recent change to vsapi allows visas to be sent back with this call.
    async fn register_vss(
        self: Rc<Self>,
        _: vsapi::v_s_handle::RegisterVssParams,
        _: vsapi::v_s_handle::RegisterVssResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "register_vss from {:?}", self.node.get_cn());
        Err(capnp::Error::unimplemented(
            "method v_s_handle::Server::register_vss not implemented".to_string(),
        ))
    }

    async fn authorize_connect(
        self: Rc<Self>,
        _: vsapi::v_s_handle::AuthorizeConnectParams,
        _: vsapi::v_s_handle::AuthorizeConnectResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "authorize_connect from {:?}", self.node.get_cn());
        Err(capnp::Error::unimplemented(
            "method v_s_handle::Server::authorize_connect not implemented".to_string(),
        ))
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

        match self.asm.cc.disconnect(zpr_addr, reason).await {
            Ok(()) => (),
            Err(e) => {
                warn!(target: VSAPI, "error processing disconnect of {}: {}", zpr_addr, e);
                let res_builder = resp.get().init_res();
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::Internal,
                    "internal error during disconnect",
                );
                return Ok(());
            }
        }

        let mut res_builder = resp.get().init_res();
        res_builder.set_ok(());
        Ok(())
    }

    async fn visa_request(
        self: Rc<Self>,
        _: vsapi::v_s_handle::VisaRequestParams,
        _: vsapi::v_s_handle::VisaRequestResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: VSAPI, "visa_request from {:?}", self.node.get_cn());
        Err(capnp::Error::unimplemented(
            "method v_s_handle::Server::visa_request not implemented".to_string(),
        ))
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

/// CParam models the TLV style connect parameters in the initial connect request for a node.
#[derive(Debug, Clone)]
struct CParam {
    name: String,
    value: CParamValue,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum CParamValue {
    String(String),
    U64(u64),
    Ipv4(std::net::Ipv4Addr),
    Ipv6(std::net::Ipv6Addr),
}

impl CParam {
    /// Parse no more than `limit` params out of the connect request.
    fn from_connect_request(
        vscr: &vsapi::v_s_connect_request::Reader,
        limit: usize,
    ) -> Result<Vec<CParam>, VSError> {
        let mut results = Vec::new();
        let params = vscr.get_params()?;
        for param in params.iter() {
            let pname = param.get_name()?.to_string()?;
            let ptype = param.get_ptype()?;
            let pval = param.get_value()?;
            match ptype {
                vsapi::ParamT::String => {
                    let sval = std::str::from_utf8(pval)?.to_string();
                    results.push(CParam {
                        name: pname,
                        value: CParamValue::String(sval),
                    });
                }
                // TODO: This doesn't seem right... we should use a capn proto union or something so
                // that we are not serializing u64.
                vsapi::ParamT::U64 => {
                    if pval.len() != 8 {
                        return Err(VSError::ParamError(format!(
                            "CParam::from_connect_request: U64 param {} has invalid length {}",
                            pname,
                            pval.len()
                        )));
                    }
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&pval[0..8]);
                    let uval = u64::from_be_bytes(arr);
                    results.push(CParam {
                        name: pname,
                        value: CParamValue::U64(uval),
                    });
                }
                vsapi::ParamT::Ipv4 => {
                    if pval.len() != 4 {
                        return Err(VSError::ParamError(format!(
                            "CParam::from_connect_request: Ipv4 param {} has invalid length {}",
                            pname,
                            pval.len()
                        )));
                    }
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&pval[0..4]);
                    let ipv4 = std::net::Ipv4Addr::from(arr);
                    results.push(CParam {
                        name: pname,
                        value: CParamValue::Ipv4(ipv4),
                    });
                }
                vsapi::ParamT::Ipv6 => {
                    if pval.len() != 16 {
                        return Err(VSError::ParamError(format!(
                            "CParam::from_connect_request: Ipv6 param {} has invalid length {}",
                            pname,
                            pval.len()
                        )));
                    }
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&pval[0..16]);
                    let ipv6 = std::net::Ipv6Addr::from(arr);
                    results.push(CParam {
                        name: pname,
                        value: CParamValue::Ipv6(ipv6),
                    });
                }
            }
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    /// Helper to extract an IpAddr type param with given key from a list.
    fn get_ipaddr(params: &[CParam], name: &str) -> Result<IpAddr, VSError> {
        for pp in params {
            if pp.name == name {
                match &pp.value {
                    CParamValue::Ipv4(ipv4) => {
                        return Ok(IpAddr::V4(*ipv4));
                    }
                    CParamValue::Ipv6(ipv6) => {
                        return Ok(IpAddr::V6(*ipv6));
                    }
                    _ => {
                        return Err(VSError::ParamError(format!(
                            "param {name} has invalid type",
                        )));
                    }
                }
            }
        }
        Err(VSError::ParamError(format!("param {name} not found")))
    }

    /// Helper to extract a String type param with given key from a list.
    fn get_string(params: &[CParam], name: &str) -> Result<String, VSError> {
        for pp in params {
            if pp.name == name {
                match &pp.value {
                    CParamValue::String(s) => {
                        return Ok(s.clone());
                    }
                    _ => {
                        return Err(VSError::ParamError(format!(
                            "param {name} has invalid type",
                        )));
                    }
                }
            }
        }
        Err(VSError::ParamError(format!("param {name} not found")))
    }
}
