//! HTTPS admin service implementation.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use libeval::attribute::{ROLE_NODE, key};
use tracing::{debug, error, info, warn};

use axum::{
    Json,
    Router,
    //routing::post,
    extract::{Json as EJson, Path as EPath, Query, Request, State},
    //extract::Form,
    http::StatusCode,
    response::IntoResponse,
    //response::Response,
    routing::{delete, get, post},
};

use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tower_service::Service;

use zpr::vsapi_types::DockPep;

use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::assembly::Assembly;
use crate::db::Role;
use crate::logging::targets::ADMIN;

use admin_api_types::{
    ActorDescriptor, AuthRevokeDescriptor, CnEntry, ListEntry, NamedListEntry, PolicyBundle,
    Revokes, ServiceDescriptor, VisaDescriptor,
};

// Must use tokio RwLock here becuase we need state to be Send.
type SharedState = Arc<tokio::sync::RwLock<AdminState>>;

#[allow(dead_code)]
struct AdminState {
    asm: Arc<Assembly>,
}

#[derive(Deserialize, Debug)]
struct RoleFilter {
    role: Option<ActorRole>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum ActorRole {
    Node,
    Adapter,
}

/// Blocking start of the admin server.
/// TODO: Do I need a handle or something to stop this cleanly?
pub async fn start_admin_server(
    key_file: &Path,
    cert_file: &Path,
    listen: SocketAddr,
    asm: &Arc<Assembly>,
) {
    info!(target: ADMIN, "admin service starting");
    let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
    serve(
        rustls_tls_acceptor(key_file, cert_file),
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

fn rustls_tls_acceptor(key_file: &Path, cert_file: &Path) -> TlsAcceptor {
    let cert_pem = std::fs::read(cert_file).expect("failed to read admin cert file");
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .expect("failed to parse admin cert PEM");

    let key_pem = std::fs::read(key_file).expect("failed to read admin key file");
    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("failed to parse admin key PEM")
        .expect("no private key found in admin key file");

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("failed to build rustls ServerConfig");

    TlsAcceptor::from(Arc::new(cfg))
}

fn admin_app(state: SharedState) -> Router {
    Router::new()
        .route("/admin/policies", get(get_policies))
        .route("/admin/policies/{capture}", get(get_policy))
        .route("/admin/policies/curr", get(get_curr_policy))
        .route("/admin/policies", post(install_policy))
        .route("/admin/visas", get(get_visas).with_state(state.clone()))
        .route("/admin/visas/{capture}", get(get_visa))
        .route("/admin/visas/{capture}", delete(revoke_visa))
        .route("/admin/actors", get(get_actors).with_state(state.clone()))
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

async fn serve(tls_acceptor: TlsAcceptor, listen: SocketAddr, state: SharedState) {
    let app = admin_app(state);
    let listener = TcpListener::bind(listen).await.unwrap_or_else(|e| {
        panic!("failed to bind admin https listener on {listen}: {e}");
    });
    info!(target: ADMIN, "admin https service listening on {listen} (TLS)");

    loop {
        let tower_service = app.clone();
        let tls_acceptor = tls_acceptor.clone();
        let (cnx, addr) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let stream = match tls_acceptor.accept(cnx).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!(target: ADMIN, "error during TLS handshake from {addr}, Error {e}");
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
                warn!(target: ADMIN, "error serving admin connection from {addr}: {}", e);
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
    debug!(target: ADMIN, "GET /admin/policies");
    two_elem_list()
}

async fn get_policy(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/policies/{}", id);
    let pb = PolicyBundle {
        config_id: 0,
        version: "v".to_string(),
        format: "f".to_string(),
        container: "c".to_string(),
    };

    (StatusCode::OK, Json(pb)).into_response()
}

async fn get_curr_policy() -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/policies/curr");
    let pb = PolicyBundle {
        config_id: 0,
        version: "v".to_string(),
        format: "f".to_string(),
        container: "c".to_string(),
    };

    (StatusCode::OK, Json(pb)).into_response()
}

async fn install_policy(EJson(_body): EJson<PolicyBundle>) -> impl IntoResponse {
    debug!(target: ADMIN, "POST /admin/policies");
    let le = ListEntry { id: 0 };
    (StatusCode::OK, Json(le)).into_response()
}

/// Returns a list of visa IDs in ListEntry structs or empty list.
#[axum::debug_handler]
//async fn get_visas(State(state): State<SharedState>) -> impl IntoResponse {
async fn get_visas(State(state): State<SharedState>) -> (StatusCode, Json<Vec<ListEntry>>) {
    debug!(target: ADMIN, "GET /admin/visas");
    let rstate = state.read().await;

    // TODO: The API does not include details on how to do pagination.
    match rstate.asm.visa_mgr.list_all_visa_ids().await {
        Err(e) => {
            error!(target: ADMIN, "error listing visa IDs: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<ListEntry>::new()),
            );
        }
        Ok(visa_ids) => {
            let le_list: Vec<ListEntry> = visa_ids.into_iter().map(|id| ListEntry { id }).collect();
            return (StatusCode::OK, Json(le_list));
        }
    }
}

fn system_time_to_unix_milliseconds(st: std::time::SystemTime) -> u64 {
    match st.duration_since(std::time::UNIX_EPOCH) {
        Ok(dur) => dur.as_millis() as u64,
        Err(_) => 0,
    }
}

fn ports_from_pep(pep: &DockPep) -> (u16, u16) {
    match pep {
        DockPep::TCP(tu_pep) => (tu_pep.source_port, tu_pep.dest_port),
        DockPep::UDP(tu_pep) => (tu_pep.source_port, tu_pep.dest_port),
        DockPep::ICMP(icmp_pep) => (icmp_pep.icmp_type as u16, icmp_pep.icmp_code as u16),
    }
}

async fn get_visa(
    State(state): State<SharedState>,
    EPath(id): EPath<u64>,
) -> Result<Json<VisaDescriptor>, StatusCode> {
    debug!(target: ADMIN, "GET /admin/visas/{}", id);
    let rstate = state.read().await;

    match rstate.asm.visa_mgr.get_visa_by_id(id).await {
        Err(e) => {
            error!(target: ADMIN, "error getting visa {}: {}", id, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(opt_visa) => match opt_visa {
            None => Err(StatusCode::NOT_FOUND),
            Some(visa) => {
                let (source_port, dest_port) = ports_from_pep(&visa.dock_pep);

                let (ctime, requesting_node) = match rstate
                    .asm
                    .visa_mgr
                    .get_visa_metadata_by_id(visa.issuer_id)
                    .await
                {
                    Ok(metadata) => match metadata {
                        Some(md) => (md.ctime, md.requesting_node.to_string()),
                        None => (0, "".to_string()),
                    },
                    Err(e) => {
                        error!(
                            target: ADMIN,
                            "error getting visa metadata for visa {}: {}", id, e
                        );
                        (0, "".to_string())
                    }
                };
                let vd = VisaDescriptor {
                    id: visa.issuer_id,
                    expires: system_time_to_unix_milliseconds(visa.expires),
                    created: ctime,
                    requesting_node,
                    policy_id: "0".into(), // TODO: not tracked yet
                    source_addr: visa.source_addr.to_string(),
                    dest_addr: visa.dest_addr.to_string(),
                    source_port,
                    dest_port,
                    proto: "TCP".into(),
                };
                return Ok(Json(vd));
            }
        },
    }
}

async fn revoke_visa(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "DELETE /admin/visas/{}", id);
    let r = Revokes {
        id: "i".to_string(),
        revoked: vec![0],
    };

    (StatusCode::OK, Json(r)).into_response()
}

/// Returns a list of connected CN values in CnEntry structs or empty list.
async fn get_actors(
    State(state): State<SharedState>,
    Query(q): Query<RoleFilter>,
) -> (StatusCode, Json<Vec<CnEntry>>) {
    debug!(target: ADMIN, "GET /admin/actors {:?}", q);
    let db_filter = match q.role {
        Some(ActorRole::Node) => Some(Role::Node),
        Some(ActorRole::Adapter) => Some(Role::Adapter),
        None => None,
    };

    let rstate = state.read().await;
    match rstate.asm.actor_mgr.list_actor_cns(db_filter).await {
        Err(e) => {
            error!(target: ADMIN, "error listing connected actors: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<CnEntry>::new()),
            )
        }
        Ok(cns) => {
            let cn_list: Vec<CnEntry> = cns.into_iter().map(|cn| CnEntry { cn }).collect();
            (StatusCode::OK, Json(cn_list))
        }
    }
}

async fn get_actor(
    State(state): State<SharedState>,
    EPath(cn): EPath<String>,
) -> Result<Json<ActorDescriptor>, StatusCode> {
    debug!(target: ADMIN, "GET /admin/actor/{}", cn);
    let rstate = state.read().await;

    match rstate.asm.actor_mgr.get_actor_by_cn(&cn).await {
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Ok(opt_a) => match opt_a {
            None => Err(StatusCode::NOT_FOUND),
            Some(actor) => {
                let ident = match actor.get_identity() {
                    Some(id) => id.join("|"),
                    None => "".to_string(),
                };

                let is_node = match actor.get_attribute(key::ROLE) {
                    Some(role_attr) => {
                        if let Ok(role_val) = role_attr.get_single_value() {
                            role_val == ROLE_NODE
                        } else {
                            false
                        }
                    }
                    _ => false,
                };

                let zpr_addr_str = match actor.get_zpr_addr() {
                    Some(addr) => addr.to_string(),
                    None => "".to_string(),
                };

                let descriptor = ActorDescriptor {
                    cn: cn.clone(),
                    ctime: 0, // TODO: Not tracked yet
                    ident,
                    node: is_node,
                    zpr_addr: zpr_addr_str,
                    node_details: None, // TODO
                };
                return Ok(Json(descriptor));
            }
        },
    }
}

async fn revoke_actor(EPath(cn): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "DELETE /admin/actors/{}", cn);
    let r = Revokes {
        id: "i".to_string(),
        revoked: vec![0, 1, 2],
    };

    (StatusCode::OK, Json(r)).into_response()
}

async fn get_related_visas(EPath(cn): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/actors/{}/visas", cn);
    two_elem_list()
}

async fn get_services(State(state): State<SharedState>) -> (StatusCode, Json<Vec<NamedListEntry>>) {
    debug!(target: ADMIN, "GET /admin/services");
    let rstate = state.read().await;

    match rstate.asm.actor_mgr.get_services_list().await {
        Err(e) => {
            error!(target: ADMIN, "error listing services: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<NamedListEntry>::new()),
            )
        }
        Ok(services) => {
            let sle_list: Vec<NamedListEntry> = services
                .into_iter()
                .map(|se| NamedListEntry { id: se.name })
                .collect();
            (StatusCode::OK, Json(sle_list))
        }
    }
}

async fn get_service(
    State(state): State<SharedState>,
    EPath(cn): EPath<String>,
) -> Result<Json<ServiceDescriptor>, StatusCode> {
    debug!(target: ADMIN, "GET /admin/service CN={}", cn);
    let rstate = state.read().await;

    if let Some(detail) = rstate.asm.actor_mgr.get_service_detail(&cn).await.unwrap() {
        let connect_via = match detail.connect_via.as_ref() {
            Some(cv_addr) => cv_addr.to_string(),
            None => "".to_string(),
        };
        let sd = ServiceDescriptor {
            service_name: detail.service_name,
            zpr_addr: detail.zpr_addr.to_string(),
            actor_cn: detail.actor_cn,
            dock_zpr_addr: connect_via,
        };
        return Ok(Json(sd));
    }

    Err(StatusCode::NOT_FOUND)
}

async fn get_revokes() -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/authrevoke");
    two_elem_list()
}

async fn get_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "GET /admin/authrevoke/{}", id);
    let ard: AuthRevokeDescriptor = AuthRevokeDescriptor {
        ty: "t".to_string(),
        cn: "c".to_string(),
    };

    (StatusCode::OK, Json(ard)).into_response()
}

async fn clear_revokes() -> impl IntoResponse {
    debug!(target: ADMIN, "POST /admin/authrevoke/clear");
    two_elem_list()
}

async fn remove_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "DELETE /admin/authrevoke/{}", id);
    let le = ListEntry { id: 0 };
    (StatusCode::OK, Json(le)).into_response()
}

async fn add_revoke(EPath(id): EPath<String>) -> impl IntoResponse {
    debug!(target: ADMIN, "POST /admin/authrevoke/{}", id);

    let le = ListEntry { id: 0 };
    (StatusCode::OK, Json(le)).into_response()
}

#[cfg(test)]
mod tests {

    use super::*;

    use axum::body::Body;
    use http_body_util::BodyExt;
    use libeval::eval::{Direction, Hit};
    use std::net::IpAddr;
    use tower::ServiceExt;
    use zpr::vsapi_types::PacketDesc;

    use crate::assembly::tests::new_assembly_for_tests;
    use crate::test_helpers::{make_adapter_actor_defexp, make_node_actor_defexp};

    #[tokio::test]
    async fn test_get_visas_no_visas() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert!(visas.is_empty());
    }

    #[tokio::test]
    async fn test_get_visas_one_visa() {
        let asm = Arc::new(new_assembly_for_tests(None).await);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let pdesc =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);

        // Add a visa.
        let v = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc, &hit)
            .await
            .unwrap();

        let created_id = v.issuer_id;
        assert!(created_id > 0);

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(visas.len(), 1);
        assert_eq!(visas[0].id, created_id);
    }

    #[tokio::test]
    async fn test_get_visas_three_visas() {
        let asm = Arc::new(new_assembly_for_tests(None).await);

        let node_addr: IpAddr = "fd5a:5052:90de::1".parse().unwrap();
        let hit = Hit::new_no_signal(0, Direction::Forward);

        // Add three visas with distinct packet descriptors.
        let pdesc0 =
            PacketDesc::new_tcp("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80).unwrap();
        let pdesc1 =
            PacketDesc::new_tcp("fd5a:5052:3000::3", "fd5a:5052:3000::4", 12346, 443).unwrap();
        let pdesc2 =
            PacketDesc::new_tcp("fd5a:5052:3000::5", "fd5a:5052:3000::6", 12347, 22).unwrap();

        let v0 = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc0, &hit)
            .await
            .unwrap();
        let v1 = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc1, &hit)
            .await
            .unwrap();
        let v2 = asm
            .visa_mgr
            .create_visa(&node_addr, &pdesc2, &hit)
            .await
            .unwrap();

        let mut created_ids = vec![v0.issuer_id, v1.issuer_id, v2.issuer_id];
        created_ids.sort_unstable();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/visas")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let visas: Vec<ListEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(visas.len(), 3);

        let mut returned_ids: Vec<u64> = visas.into_iter().map(|v| v.id).collect();
        returned_ids.sort_unstable();
        assert_eq!(returned_ids, created_ids);
    }

    #[tokio::test]
    async fn test_get_actors_no_actors() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let actors: Vec<CnEntry> = serde_json::from_slice(&body).unwrap();
        assert!(actors.is_empty());
    }

    #[tokio::test]
    async fn test_get_actors_one_actor() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let actor = make_node_actor_defexp("fd5a:5052::10", "node-1", "[fd5a:5052::100]:1234");
        asm.actor_mgr.add_node(&actor).await.unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let actors: Vec<CnEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(actors.len(), 1);
        assert_eq!(actors[0].cn, "node-1");
    }

    #[tokio::test]
    async fn test_get_actors_multiple_actors() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let actor0 = make_node_actor_defexp("fd5a:5052::11", "node-1", "[fd5a:5052::101]:1234");
        let actor1 = make_node_actor_defexp("fd5a:5052::12", "node-2", "[fd5a:5052::102]:1234");
        let actor2 = make_node_actor_defexp("fd5a:5052::13", "node-3", "[fd5a:5052::103]:1234");

        asm.actor_mgr.add_node(&actor0).await.unwrap();
        asm.actor_mgr.add_node(&actor1).await.unwrap();
        asm.actor_mgr.add_node(&actor2).await.unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();

        let mut actors: Vec<CnEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(actors.len(), 3);
        actors.sort_by(|a, b| a.cn.cmp(&b.cn));
        let actor_cns: Vec<String> = actors.into_iter().map(|a| a.cn).collect();
        assert_eq!(
            actor_cns,
            vec![
                "node-1".to_string(),
                "node-2".to_string(),
                "node-3".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_get_actors_role_filter() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let node_actor = make_node_actor_defexp("fd5a:5052::20", "node-1", "[fd5a:5052::120]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::21", "adapter-1");

        asm.actor_mgr.add_node(&node_actor).await.unwrap();
        asm.actor_mgr
            .add_adapter_via_node(&adapter_actor, node_actor.get_zpr_addr().unwrap())
            .await
            .unwrap();

        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        let response_nodes = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors?role=node")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response_nodes.status(), StatusCode::OK);

        let body_nodes = response_nodes
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let actors_nodes: Vec<CnEntry> = serde_json::from_slice(&body_nodes).unwrap();
        assert_eq!(actors_nodes.len(), 1);
        assert_eq!(actors_nodes[0].cn, "node-1");

        let response_adapters = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors?role=adapter")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response_adapters.status(), StatusCode::OK);

        let body_adapters = response_adapters
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let actors_adapters: Vec<CnEntry> = serde_json::from_slice(&body_adapters).unwrap();
        assert_eq!(actors_adapters.len(), 1);
        assert_eq!(actors_adapters[0].cn, "adapter-1");
    }

    #[tokio::test]
    async fn test_get_actors_invalid_role_filter() {
        let asm = Arc::new(new_assembly_for_tests(None).await);
        let shared_state = Arc::new(tokio::sync::RwLock::new(AdminState::new(asm.clone())));
        let app = admin_app(shared_state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/actors?role=invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
