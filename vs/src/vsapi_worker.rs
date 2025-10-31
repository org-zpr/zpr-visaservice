use openssl::rand::rand_bytes;
use tokio_util::compat::*;

use vsapi::vs_capnp as vsapi;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

use crate::assembly::Assembly;
use crate::error::VSError;
use crate::logging::targets::VSAPI;
use crate::zpr;

pub async fn launch_capnp(
    asm: Arc<Assembly>,
    listen: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
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

use std::cell::Cell;

#[allow(dead_code)]
struct VSGateImpl {
    asm: Arc<Assembly>,
    remote: SocketAddr,
    remote_cn: String,

    // This is set in `challenge` call and read in the `authenticate` call.
    // My understanding is that the VSGateImpl instance here is tied to the connection
    // which I think runs operations one at a time so this should be safe
    // to use.
    challenge_data: Cell<[u8; 32]>,
}

#[allow(dead_code)]
struct VSHandleImpl {
    // TODO: Will include more info about the authenticated node.
    asm: Arc<Assembly>,
}

impl VSGateImpl {
    #[allow(dead_code)]
    fn new(asm: Arc<Assembly>, remote: SocketAddr, remote_cn: String) -> Self {
        VSGateImpl {
            asm,
            remote,
            remote_cn,
            challenge_data: Cell::new([0u8; 32]),
        }
    }
}

impl VSHandleImpl {
    fn new(asm: Arc<Assembly>) -> Self {
        VSHandleImpl { asm }
    }
}

fn write_error(bldr: &mut vsapi::error::Builder, code: vsapi::ErrorCode, message: &str) {
    bldr.set_code(code);
    bldr.set_message(message);
    bldr.set_retry_in(0);
}

impl vsapi::visa_service::Server for VisaServiceImpl {
    fn connect(
        &self,
        params: vsapi::visa_service::ConnectParams,
        mut results: vsapi::visa_service::ConnectResults,
    ) -> impl Future<Output = Result<(), ::capnp::Error>> + '_ {
        async move {
            let req_cn = params.get()?.get_req()?.get_cn()?.to_string()?;
            let req_type = params.get()?.get_req()?.get_ctype()?;
            // List of connection params ignored for now (TODO)
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

            let vs_gate: vsapi::v_s_gate::Client =
                capnp_rpc::new_client(VSGateImpl::new(self.asm.clone(), self.remote, req_cn));

            //res_builder.reborrow().set_ok(vs_gate)?;
            res_builder.set_ok(vs_gate)?;

            Ok(())
        }
    }
}

impl vsapi::v_s_gate::Server for VSGateImpl {
    fn challenge(
        &self,
        _params: vsapi::v_s_gate::ChallengeParams,
        mut results: vsapi::v_s_gate::ChallengeResults,
    ) -> impl Future<Output = Result<(), ::capnp::Error>> + '_ {
        async move {
            let mut res_builder = results.get().init_challenge();
            res_builder.set_alg(vsapi::ChallengeAlg::RsaSha256Pkcs1v15);
            let mut challenge_data = [0u8; 32];
            rand_bytes(&mut challenge_data).unwrap();
            res_builder.set_bytes(&challenge_data);
            self.challenge_data.set(challenge_data);
            Ok(())
        }
    }

    fn authenticate(
        &self,
        params: vsapi::v_s_gate::AuthenticateParams,
        mut results: vsapi::v_s_gate::AuthenticateResults,
    ) -> impl Future<Output = Result<(), ::capnp::Error>> + '_ {
        async move {
            let cresp = params.get()?.get_cresp()?; // has challenge (bytes), timestamp (uint64), bytes (bytes)
            let mut res_builder = results.get().init_res();
            let challenge_presented = cresp.get_challenge()?;
            // Must match the challenge we sent.
            if challenge_presented != &self.challenge_data.get() {
                let mut err_builder = res_builder.init_error();
                write_error(
                    &mut err_builder,
                    vsapi::ErrorCode::InvalidOperation, // TODO: New code 'AuthError'
                    "invalid challenge",
                );
                return Ok(());
            }

            // Time must be within acceptable range.
            let unix_ts = cresp.get_timestamp();
            let now = SystemTime::now();
            let my_unix_ts = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
            if my_unix_ts.abs_diff(unix_ts) > zpr::MAX_CLOCK_SKEW_SECS {
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
            let node_id = match self
                .asm
                .cc
                .authenticate_node(
                    challenge_presented,
                    unix_ts,
                    &self.remote_cn,
                    challenge_response,
                )
                .await
            {
                Ok(node_id) => node_id,
                Err(VSError::AuthenticationFailed) => {
                    let mut err_builder = res_builder.init_error();
                    write_error(
                        &mut err_builder,
                        vsapi::ErrorCode::InvalidOperation, // TODO: New code 'AuthError'
                        "authentication failed",
                    );
                    return Ok(());
                }
                Err(_e) => {
                    let mut err_builder = res_builder.init_error();
                    write_error(
                        &mut err_builder,
                        vsapi::ErrorCode::Internal,
                        "internal error during authentication",
                    );
                    return Ok(());
                }
            };

            info!(
                "successfully authenticated node {} from {}",
                node_id.cn, self.remote
            );

            // If ok return our VSHandle.
            let vs_handle: vsapi::v_s_handle::Client =
                capnp_rpc::new_client(VSHandleImpl::new(self.asm.clone()));
            res_builder.set_ok(vs_handle)?;
            Ok(())
        }
    }
}

impl vsapi::v_s_handle::Server for VSHandleImpl {
    fn register_vss(
        &self,
        _: vsapi::v_s_handle::RegisterVssParams,
        _: vsapi::v_s_handle::RegisterVssResults,
    ) -> impl Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method v_s_handle::Server::register_vss not implemented".to_string(),
            ))
        }
    }
    fn authorize_connect(
        &self,
        _: vsapi::v_s_handle::AuthorizeConnectParams,
        _: vsapi::v_s_handle::AuthorizeConnectResults,
    ) -> impl Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method v_s_handle::Server::authorize_connect not implemented".to_string(),
            ))
        }
    }
    fn reauthorize(
        &self,
        _: vsapi::v_s_handle::ReauthorizeParams,
        _: vsapi::v_s_handle::ReauthorizeResults,
    ) -> impl Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method v_s_handle::Server::reauthorize not implemented".to_string(),
            ))
        }
    }
    fn notify_disconnect(
        &self,
        _: vsapi::v_s_handle::NotifyDisconnectParams,
        _: vsapi::v_s_handle::NotifyDisconnectResults,
    ) -> impl Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method v_s_handle::Server::notify_disconnect not implemented".to_string(),
            ))
        }
    }
    fn visa_request(
        &self,
        _: vsapi::v_s_handle::VisaRequestParams,
        _: vsapi::v_s_handle::VisaRequestResults,
    ) -> impl Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method v_s_handle::Server::visa_request not implemented".to_string(),
            ))
        }
    }
    fn ping(
        &self,
        _: vsapi::v_s_handle::PingParams,
        _: vsapi::v_s_handle::PingResults,
    ) -> impl Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method v_s_handle::Server::ping not implemented".to_string(),
            ))
        }
    }
}
