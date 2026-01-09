//! HTTPS admin service implementation.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use tracing::{error, info, warn};

use axum::{
    Json,
    Router,
    //routing::post,
    body::Body,
    //body::Body,
    extract::{Request, State},
    //extract::Form,
    http::StatusCode,
    //response::Response,
    routing::get,
};

use futures_util::pin_mut;

use http_body_util::BodyExt;
use hyper::Response;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;

use tokio::net::TcpListener;
use tokio_native_tls::{
    TlsAcceptor,
    native_tls::{Identity, Protocol, TlsAcceptor as NativeTlsAcceptor},
};

use crate::assembly::Assembly;
use crate::logging::targets::HTADMIN;
use http::Method;

use admin_api_types::admin_api_types::{
    ActorDescriptor, AuthRevokeDescriptor, ListEntry, NodeRecordBrief, PolicyBundle, Revokes,
    ServiceDescriptor, VisaDescriptor,
};

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
        .route("/status", get(admin_status_handler))
        .with_state(state.clone())
}

async fn serve(acceptor: NativeTlsAcceptor, listen: SocketAddr, state: SharedState) {
    let _app = admin_app(state);
    let tls_acceptor = TlsAcceptor::from(acceptor);
    let listener = TcpListener::bind(listen).await.unwrap_or_else(|e| {
        panic!("failed to bind admin https listener on {listen}: {e}");
    });
    info!(target: HTADMIN, "admin https service listening on {listen} (TLS)");

    pin_mut!(listener);

    loop {
        let tls_acceptor: TlsAcceptor = tls_acceptor.clone();
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
                async move {
                    let (parts, body) = req.into_parts();

                    let mut path: Vec<&str> = parts.uri.path().split('/').collect();
                    let method = parts.clone().method;

                    info!(target: HTADMIN, "received HTTP request: {parts:?}", );

                    if path[0] == "" {
                        path.remove(0);
                    }
                    if path.len() < 2 {
                        // ERROR HERE
                        warn!(target: HTADMIN, "Error in format from {addr}");
                    }
                    println!("{path:?}");
                    match path[1] {
                        "policies" => match path.len() {
                            // GET /admin/policies
                            2 => get_policies(),
                            // GET /admin/policies/{ID}
                            3 => get_policy(path[2]),
                            _ => bad_request(),
                        },
                        "policy" => match method {
                            // GET /admin/policy
                            Method::GET => get_curr_policy(),
                            // POST /admin/policy
                            Method::POST => install_policy(body).await,
                            _ => bad_request(),
                        },
                        "visas" => match method {
                            // DELETE /admin/visas/{ID}
                            Method::DELETE => revoke_visa(path[2]),
                            Method::GET => match path.len() {
                                // GET /admin/visas
                                2 => get_visas(),
                                // GET /admin/visas/{ID}
                                3 => get_visa(path[2]),
                                _ => bad_request(),
                            },
                            _ => bad_request(),
                        },
                        "actors" => match parts.uri.query() {
                            // GET /admin/actors?role=node
                            Some(_) => get_nodes(),
                            None => match method {
                                // DELETE /admin/actors/{CN}
                                Method::DELETE => revoke_actor(path[2]),
                                Method::GET => match path.len() {
                                    // GET /admin/actors
                                    2 => get_actors(),
                                    // GET /admin/actors/{CN}
                                    3 => get_actor(path[2]),
                                    // GET /admin/actors/{CN}/visas
                                    4 => get_related_visas(path[2]),
                                    _ => bad_request(),
                                },
                                _ => bad_request(),
                            },
                        },
                        "services" => match path.len() {
                            // GET /admin/services
                            2 => get_services(),
                            // GEt /admin/services/{CN}
                            3 => get_service(path[2]),
                            _ => bad_request(),
                        },
                        "authrevoke" => match (method, path.len()) {
                            // GET /admin/authrevoke
                            (Method::GET, 2) => get_revokes(),
                            // GET /admin/authrevoke/{ID}
                            (Method::GET, 3) => get_revoke(path[2]),
                            // POST /admin/authrevoke
                            (Method::POST, 2) => add_revoke(body).await,
                            // POST /admin/authrevoke/clear
                            (Method::POST, 3) => clear_revokes(),
                            // DELETE /admin/authrevoke/{ID}
                            (Method::DELETE, 3) => remove_revoke(path[2]),
                            _ => bad_request(),
                        },
                        _ => bad_request(),
                    }
                }
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

fn bad_request() -> Result<Response<Body>, std::convert::Infallible> {
    let resp = Response::builder()
        .status(400)
        .body(Body::from("Not an accepted request"))
        .unwrap();
    Ok(resp)
}

fn two_elem_list() -> Result<Response<Body>, std::convert::Infallible> {
    let le0 = ListEntry { id: 0 };
    let le1 = ListEntry { id: 1 };
    let json = serde_json::to_string(&vec![le0, le1]).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn get_policies() -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/policies");
    two_elem_list()
}

fn get_policy(id: &str) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/policies/{}", id);
    let pb = PolicyBundle {
        config_id: 0,
        version: "v".to_string(),
        format: "f".to_string(),
        container: "c".to_string(),
    };
    let json = serde_json::to_string(&pb).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn get_curr_policy() -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/policy");
    let pb = PolicyBundle {
        config_id: 0,
        version: "v".to_string(),
        format: "f".to_string(),
        container: "c".to_string(),
    };
    let json = serde_json::to_string(&pb).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

async fn install_policy(body: Incoming) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "POST /admin/policy");
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            let resp = Response::builder()
                .status(400)
                .body(Body::from(format!("Failed to read body {err}")))
                .unwrap();
            return Ok(resp);
        }
    };

    let _pb: PolicyBundle = match serde_json::from_slice(&bytes) {
        Ok(pb) => pb,
        Err(err) => {
            let resp = Response::builder()
                .status(400)
                .body(Body::from(format!("Failed to read body {err}")))
                .unwrap();
            return Ok(resp);
        }
    };

    let le = ListEntry { id: 0 };
    let json = serde_json::to_string(&le).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn get_visas() -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/visas");
    two_elem_list()
}

fn get_visa(id: &str) -> Result<Response<Body>, std::convert::Infallible> {
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
    let json = serde_json::to_string(&vd).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn revoke_visa(id: &str) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "DELETE /admin/visas/{}", id);
    let r = Revokes {
        id: "i".to_string(),
        revoked: vec![0],
    };
    let json = serde_json::to_string(&r).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn get_actors() -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/actors");
    two_elem_list()
}

fn get_nodes() -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/actors?role=node");
    two_elem_list()
}

fn get_actor(id: &str) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/actors/{}", id);
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
    let json = serde_json::to_string(&ad).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn revoke_actor(id: &str) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "DELETE /admin/actors/{}", id);
    let r = Revokes {
        id: "i".to_string(),
        revoked: vec![0, 1, 2],
    };
    let json = serde_json::to_string(&r).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn get_related_visas(cn: &str) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/actors/{}/visas", cn);
    two_elem_list()
}

fn get_services() -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/actors");
    two_elem_list()
}

fn get_service(id: &str) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/actors/{}", id);
    let sd = ServiceDescriptor { id: 0, actor_id: 0 };

    let json = serde_json::to_string(&sd).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn get_revokes() -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/authrevoke");
    let le0 = ListEntry { id: 0 };
    let le1 = ListEntry { id: 1 };
    let json = serde_json::to_string(&vec![le0, le1]).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn get_revoke(id: &str) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "GET /admin/visas/{}", id);
    let ard: AuthRevokeDescriptor = AuthRevokeDescriptor {
        ty: "t".to_string(),
        cn: "c".to_string(),
    };
    let json = serde_json::to_string(&ard).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

fn clear_revokes() -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "POST /admin/authrevoke/clear");
    two_elem_list()
}

fn remove_revoke(id: &str) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "DELETE /admin/authrevoke/{}", id);
    let le = ListEntry { id: 0 };
    let json = serde_json::to_string(&le).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
}

async fn add_revoke(body: Incoming) -> Result<Response<Body>, std::convert::Infallible> {
    info!(target: HTADMIN, "POST /admin/authrevoke");
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            let resp = Response::builder()
                .status(400)
                .body(Body::from(format!("Failed to read body {err}")))
                .unwrap();
            return Ok(resp);
        }
    };

    let _vd: VisaDescriptor = match serde_json::from_slice(&bytes) {
        Ok(vd) => vd,
        Err(err) => {
            let resp = Response::builder()
                .status(400)
                .body(Body::from(format!("Failed to read body {err}")))
                .unwrap();
            return Ok(resp);
        }
    };

    let le = ListEntry { id: 0 };
    let json = serde_json::to_string(&le).unwrap();

    let resp = Response::new(Body::new(json));
    Ok(resp)
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
