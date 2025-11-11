//! HTTPS admin service implementation.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use tracing::{error, info, warn};

use axum::{
    Json,
    Router,
    //body::Body,
    extract::{Request, State},
    //extract::Form,
    http::StatusCode,
    //response::Response,
    routing::get,
    //routing::post,
};

use futures_util::pin_mut;
use tower_service::Service;

use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;
//use serde::Deserialize;

use tokio::net::TcpListener;
use tokio_native_tls::{
    TlsAcceptor,
    native_tls::{Identity, Protocol, TlsAcceptor as NativeTlsAcceptor},
};

use crate::assembly::Assembly;
use crate::logging::targets::HTADMIN;

type SharedState = Arc<RwLock<AdminState>>;

#[allow(dead_code)]
struct AdminState {
    asm: Arc<Assembly>,
}

/// Blocking start of the admin server.
/// TODO: Do I need a handle or something to stop this cleanly?
pub async fn start_admin_server(
    key_file: &Path,
    cert_file: &Path,
    listen: SocketAddr,
    asm: &Arc<Assembly>,
) {
    let shared_state = Arc::new(RwLock::new(AdminState::new(asm.clone())));
    serve(
        native_tls_acceptor(key_file, cert_file),
        listen,
        shared_state,
    )
    .await;
}

impl AdminState {
    pub fn new(asm: Arc<Assembly>) -> Self {
        AdminState { asm }
    }
}

fn native_tls_acceptor(key_file: &Path, cert_file: &Path) -> NativeTlsAcceptor {
    let key_pem = std::fs::read_to_string(key_file).expect("failed to read admin key file");
    let cert_pem = std::fs::read_to_string(cert_file).expect("failed to read admin cert file");
    let identity = Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes())
        .expect("failed to create identity from admin cert/key");
    NativeTlsAcceptor::builder(identity)
        .min_protocol_version(Some(Protocol::Tlsv12))
        .build()
        .expect("failed to build native TLS acceptor")
}

fn admin_app(state: SharedState) -> Router {
    Router::new()
        .route("/status", get(admin_status_handler))
        .with_state(state.clone())
}

async fn serve(acceptor: NativeTlsAcceptor, listen: SocketAddr, state: SharedState) {
    let app = admin_app(state);
    let tls_acceptor = TlsAcceptor::from(acceptor);
    let listener = TcpListener::bind(listen).await.unwrap_or_else(|e| {
        panic!("failed to bind admin https listener on {listen}: {e}");
    });
    info!(target: HTADMIN, "admin https service listening on {listen} (TLS)");

    pin_mut!(listener);

    loop {
        let tower_service = app.clone();
        let tls_acceptor = tls_acceptor.clone();

        let (cnx, addr) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let Ok(stream) = tls_acceptor.accept(cnx).await else {
                error!(target: HTADMIN, "error during TLS handshake from {addr}");
                return;
            };

            let stream = TokioIo::new(stream);
            let hyper_service = hyper::service::service_fn(move |req: Request<Incoming>| {
                tower_service.clone().call(req)
            });

            let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(stream, hyper_service)
                .await;

            if let Err(e) = ret {
                warn!(target: HTADMIN, "error serving admin connection from {addr}: {}", e);
            }
        });
    }
}

#[derive(Debug, Serialize, Default)]
pub struct AdminStatus {
    pub status: String,
}

async fn admin_status_handler(
    State(_state): State<SharedState>,
) -> (StatusCode, Json<AdminStatus>) {
    return (
        StatusCode::OK,
        Json(AdminStatus {
            status: "ok".to_string(),
        }),
    );
}
