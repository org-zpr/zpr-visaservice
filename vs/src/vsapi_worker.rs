use tokio_util::compat::*;

use vsapi::vs_capnp as vsapi;

use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

use crate::assembly::Assembly;
use crate::logging::targets::VSAPI;

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

        let vs_service: vsapi::visa_service::Client =
            capnp_rpc::new_client(VisServiceImpl { asm: asm.clone() });

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
struct VisServiceImpl {
    asm: Arc<Assembly>,
}

#[allow(dead_code)]
struct VSGateImpl {
    asm: Arc<Assembly>,
}

#[allow(dead_code)]
struct VSHandleImpl {
    asm: Arc<Assembly>,
}

impl vsapi::visa_service::Server for VisServiceImpl {
    fn connect(
        &self,
        _params: vsapi::visa_service::ConnectParams,
        _results: vsapi::visa_service::ConnectResults,
    ) -> impl ::core::future::Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method visa_service::Server::connect not implemented".to_string(),
            ))
        }
    }
}

impl vsapi::v_s_gate::Server for VSGateImpl {
    fn challenge(
        &self,
        _params: vsapi::v_s_gate::ChallengeParams,
        _results: vsapi::v_s_gate::ChallengeResults,
    ) -> impl ::core::future::Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method v_s_gate::Server::challenge not implemented".to_string(),
            ))
        }
    }

    fn authenticate(
        &self,
        _params: vsapi::v_s_gate::AuthenticateParams,
        _results: vsapi::v_s_gate::AuthenticateResults,
    ) -> impl ::core::future::Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method v_s_gate::Server::authenticate not implemented".to_string(),
            ))
        }
    }
}

impl vsapi::v_s_handle::Server for VSHandleImpl {
    fn register_vss(
        &self,
        _: vsapi::v_s_handle::RegisterVssParams,
        _: vsapi::v_s_handle::RegisterVssResults,
    ) -> impl ::core::future::Future<Output = Result<(), ::capnp::Error>> + '_ {
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
    ) -> impl ::core::future::Future<Output = Result<(), ::capnp::Error>> + '_ {
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
    ) -> impl ::core::future::Future<Output = Result<(), ::capnp::Error>> + '_ {
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
    ) -> impl ::core::future::Future<Output = Result<(), ::capnp::Error>> + '_ {
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
    ) -> impl ::core::future::Future<Output = Result<(), ::capnp::Error>> + '_ {
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
    ) -> impl ::core::future::Future<Output = Result<(), ::capnp::Error>> + '_ {
        async {
            Err(::capnp::Error::unimplemented(
                "method v_s_handle::Server::ping not implemented".to_string(),
            ))
        }
    }
}
