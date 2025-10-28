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

struct VisServiceImpl {
    asm: Arc<Assembly>,
}
struct VSGateImpl {
    asm: Arc<Assembly>,
}
struct VSHandleImpl {
    asm: Arc<Assembly>,
}

impl vsapi::visa_service::Server for VisServiceImpl {}

impl vsapi::v_s_gate::Server for VSGateImpl {}

impl vsapi::v_s_handle::Server for VSHandleImpl {}
