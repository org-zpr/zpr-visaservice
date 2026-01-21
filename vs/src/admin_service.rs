//! HTTPS admin service implementation.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use tracing::{error, info, warn};

use axum::{
    Json,
    Router,
    //routing::post,
    extract::{Json as EJson, Path as EPath, Query, Request},
    //extract::Form,
    http::StatusCode,
    response::IntoResponse,
    //response::Response,
    routing::{delete, get, post},
};

use futures_util::pin_mut;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tower_service::Service;

use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_native_tls::{
    TlsAcceptor,
    native_tls::{Identity, Protocol, TlsAcceptor as NativeTlsAcceptor},
};

use crate::assembly::Assembly;
use crate::logging::targets::HTADMIN;
use admin_api_types::admin_api_types::{
    ActorDescriptor, AuthRevokeDescriptor, ListEntry, NodeRecordBrief, PolicyBundle, Revokes,
    ServiceDescriptor, VisaDescriptor,
};

type SharedState = Arc<RwLock<AdminState>>;

#[allow(dead_code)]
struct AdminState {
    asm: Arc<Assembly>,
}

#[derive(Deserialize, Debug)]
struct Node {
    role: Option<String>,
}

/// Blocking start of the admin server.
/// TODO: Do I need a handle or something to stop this cleanly?
pub async fn start_admin_server(
    key_file: &Path,
    cert_file: &Path,
    listen: SocketAddr,
    asm: &Arc<Assembly>,
) {
    info!(target: HTADMIN, "admin service starting");
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
        .route("/admin/policies", get(get_policies))
        .route("/admin/policies/{capture}", get(get_policy))
        .route("/admin/policies/curr", get(get_curr_policy))
        .route("/admin/policies", post(install_policy))
        .route("/admin/visas", get(get_visas))
        .route("/admin/visas/{capture}", get(get_visa))
        .route("/admin/visas/{capture}", delete(revoke_visa))
        .route("/admin/actors", get(get_actors))
        .route("/admin/actors/{capture}", get(get_actor))
        .route("/admin/actors/{capture}/visas", get(get_related_visas))
        .route("/admin/actors/{capture}", delete(revoke_actor))
        .route("/admin/services", get(get_services))
        .route("/admin/services/{capture}", get(get_service))
        .route("/admin/authrevoke", get(get_revokes))
        .route("/admin/authrevoke/{capture}", get(get_revoke))
        .route("/admin/authrevoke/{capture}", post(add_revoke))
        .route("/admin/authrevoke/clear", post(clear_revokes))
        .route("/admin/authrevoke/{capture}", delete(remove_revoke))
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
            let stream = match tls_acceptor.accept(cnx).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!(target: HTADMIN, "error during TLS handshake from {addr}, Error {e}");
                    return;
                }
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

fn two_elem_list() -> impl IntoResponse {
    let le0 = ListEntry { id: 0 };
    let le1 = ListEntry { id: 1 };

    (StatusCode::OK, Json(vec![le0, le1])).into_response()
}

async fn get_policies() -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/policies");
    two_elem_list()
}

async fn get_policy(EPath(id): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/policies/{}", id);
    let pb = PolicyBundle {
        config_id: 0,
        version: "v".to_string(),
        format: "f".to_string(),
        container: "c".to_string(),
    };

    (StatusCode::OK, Json(pb)).into_response()
}

async fn get_curr_policy() -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/policies/curr");
    let pb = PolicyBundle {
        config_id: 0,
        version: "v".to_string(),
        format: "f".to_string(),
        container: "c".to_string(),
    };

    (StatusCode::OK, Json(pb)).into_response()
}

async fn install_policy(EJson(_body): EJson<PolicyBundle>) -> impl IntoResponse {
    info!(target: HTADMIN, "POST /admin/policies");

    let le = ListEntry { id: 0 };
    (StatusCode::OK, Json(le)).into_response()
}

async fn get_visas() -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/visas");
    two_elem_list()
}

async fn get_visa(EPath(id): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/visas/{}", id);
    let vd = VisaDescriptor {
        id: 0,
        expires: 0,
        created: 0,
        actor_id: "a".to_string(),
        policy_id: "p".to_string(),
        source_addr: "s".to_string(),
        dest_addr: "d".to_string(),
        source_port: "s".to_string(),
        dest_port: "d".to_string(),
        proto: "p".to_string(),
    };

    (StatusCode::OK, Json(vd)).into_response()
}

async fn revoke_visa(EPath(id): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "DELETE /admin/visas/{}", id);
    let r = Revokes {
        id: "i".to_string(),
        revoked: vec![0],
    };

    (StatusCode::OK, Json(r)).into_response()
}

async fn get_actors(Query(q): Query<Node>) -> impl IntoResponse {
    match q.role {
        Some(_) => info!(target: HTADMIN, "GET /admin/actors?role=node"),
        None => info!(target: HTADMIN, "GET /admin/actors"),
    };

    two_elem_list()
}

async fn get_actor(EPath(cn): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/actors/{}", cn);
    let nrb = NodeRecordBrief {
        pending: 0,
        last_contact: 0,
        visa_requests: 0,
        connect_requests: 0,
        in_sync: false,
    };
    let ad = ActorDescriptor {
        cn: "c".to_string(),
        ctime: 0,
        ident: "i".to_string(),
        node: false,
        zpr_addr: "z".to_string(),
        node_details: nrb,
    };

    (StatusCode::OK, Json(ad)).into_response()
}

async fn revoke_actor(EPath(cn): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "DELETE /admin/actors/{}", cn);
    let r = Revokes {
        id: "i".to_string(),
        revoked: vec![0, 1, 2],
    };

    (StatusCode::OK, Json(r)).into_response()
}

async fn get_related_visas(EPath(cn): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/actors/{}/visas", cn);
    two_elem_list()
}

async fn get_services() -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/services");
    two_elem_list()
}

async fn get_service(EPath(cn): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/services/{}", cn);
    let sd = ServiceDescriptor { id: 0, actor_id: 0 };

    (StatusCode::OK, Json(sd)).into_response()
}

async fn get_revokes() -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/authrevoke");
    two_elem_list()
}

async fn get_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "GET /admin/authrevoke/{}", id);
    let ard: AuthRevokeDescriptor = AuthRevokeDescriptor {
        ty: "t".to_string(),
        cn: "c".to_string(),
    };

    (StatusCode::OK, Json(ard)).into_response()
}

async fn clear_revokes() -> impl IntoResponse {
    info!(target: HTADMIN, "POST /admin/authrevoke/clear");
    two_elem_list()
}

async fn remove_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "DELETE /admin/authrevoke/{}", id);
    let le = ListEntry { id: 0 };
    (StatusCode::OK, Json(le)).into_response()
}

async fn add_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    info!(target: HTADMIN, "POST /admin/authrevoke/{}", id);

    let le = ListEntry { id: 0 };
    (StatusCode::OK, Json(le)).into_response()
}
