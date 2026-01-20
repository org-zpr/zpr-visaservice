//! Actor manager. Manages nodes too.
//!

use libeval::actor::Actor;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::warn;

use zpr::policy_types::{Scope, ServiceType};
use zpr::vsapi_types::ServiceDescriptor;

use crate::assembly::Assembly;
use crate::db;
use crate::error::{DBError, VSError};
use crate::logging::targets::AMGR;

pub struct ActorMgr {
    actor_db: db::ActorRepo,
    node_db: db::NodeRepo,
}

impl ActorMgr {
    pub fn new(actor_repo: db::ActorRepo, node_repo: db::NodeRepo) -> Self {
        ActorMgr {
            actor_db: actor_repo,
            node_db: node_repo,
        }
    }

    /// TODO: Support for reconnects (where we still have state).
    pub async fn add_node(&self, actor: &Actor) -> Result<(), VSError> {
        if !actor.is_node() {
            return Err(VSError::InternalError(
                "attempt to add non-node actor as node".into(),
            ));
        }
        // Make sure DB is clean (TODO: support for reconnects)
        self.node_db
            .remove_node(actor.get_zpr_addr().unwrap())
            .await?;

        self.actor_db.add_actor(actor).await?;
        let node_obj = db::Node::new_from_node_actor(&actor)?;
        self.node_db.add_node(&node_obj).await?;
        Ok(())
    }

    /// Use [ActorMgr::remove_actor_by_zpr_addr] to remove actor records which apply to both nodes and adapters.
    /// Use this function here in addition to remove node state.
    pub async fn remove_node(&self, node_addr: &IpAddr) -> Result<(), VSError> {
        self.node_db.remove_node(node_addr).await?;
        Ok(())
    }

    /// Update vss socket for given node in the DB.
    pub async fn set_node_vss(&self, node_addr: &IpAddr, vss: &SocketAddr) -> Result<(), VSError> {
        self.node_db.set_node_vss(node_addr, vss).await?;
        Ok(())
    }

    /// Add an adatpter called "magic" since it is not connected to any node.
    /// We (the visa service) uses this to connect itself at startup.
    ///
    /// TODO: At some point we need to update our state to reflect that the visa service is docked to a node.
    pub async fn add_magic_adapter(&self, actor: &Actor) -> Result<(), VSError> {
        if actor.is_node() {
            return Err(VSError::InternalError(
                "attempt to add node actor as adapter".into(),
            ));
        }
        self.actor_db.add_actor(actor).await?;
        Ok(())
    }

    /// Add an adapter that is connected to a node.
    #[allow(dead_code)]
    pub async fn add_adapter_via_node(
        &self,
        actor: &Actor,
        connected_to_node: &IpAddr,
    ) -> Result<(), VSError> {
        if actor.is_node() {
            return Err(VSError::InternalError(
                "attempt to add node actor as adapter".into(),
            ));
        }
        self.actor_db.add_actor(actor).await?;
        self.node_db
            .add_connected_adater(connected_to_node, &actor.get_zpr_addr().unwrap())
            .await?;
        Ok(())
    }

    /// Returns Ok(None) if not found.
    pub async fn get_actor_by_zpr_addr(&self, zpra: &IpAddr) -> Result<Option<Actor>, VSError> {
        match self.actor_db.get_actor_by_zpr_addr(zpra).await {
            Ok(actor) => Ok(Some(actor)),
            Err(DBError::NotFound(_)) => Ok(None),
            Err(e) => Err(VSError::from(e)),
        }
    }

    /// Remove actor state from the database. If removing a node, also call [ActorMgr::remove_node].
    pub async fn remove_actor_by_zpr_addr(&self, zpra: &IpAddr) -> Result<(), VSError> {
        Ok(self.actor_db.rm_actor_by_zpr_addr(zpra).await?)
    }

    /// Returns ZPR addresses of adapters (NOT nodes) connected to the given node.
    pub async fn get_adapters_connected_to_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<IpAddr>, VSError> {
        Ok(self
            .node_db
            .get_connected_adapters(node_addr)
            .await?
            .into_iter()
            .collect())
    }

    pub async fn get_auth_services_list(
        &self,
        asm: Arc<Assembly>,
    ) -> Result<Vec<ServiceDescriptor>, VSError> {
        // From the DB we can get the (service_name, zpr_addr) for each connected service.

        let service_entries = self.actor_db.list_services().await?;

        let mut services = Vec::new();
        let pol = asm.policy_mgr.get_current();

        let mut svc_map = HashMap::new();
        for svc in pol.list_services() {
            if matches!(svc.kind, ServiceType::Authentication) {
                svc_map.insert(svc.id.clone(), svc);
            }
        }

        for s_ent in &service_entries {
            if let Some(svc) = svc_map.get(&s_ent.name) {
                let sdesc = ServiceDescriptor {
                    service_id: svc.id.clone(),
                    service_uri: uri_for_service(
                        &svc.kind,
                        &s_ent.zpr_addr,
                        svc.endpoints.as_slice(),
                    )?,
                    zpr_addr: s_ent.zpr_addr.clone(),
                };
                services.push(sdesc);
            } else {
                // We have a service registered in the state DB but is not in policy.
                warn!(target: AMGR, "service in DB not found in policy: {}", s_ent.name);
            }
        }

        Ok(services)
    }
}

// The auth service URI is of the form: <ZPR_AUTH_SCHEME>://<addr>:<port>/path
//
// Example: zpr-oauthrsa://[fd5a:5052:9090::88]:4000
//
// The 'zpr-oauthrsa' scheme implies https and /preauthorize and /authorize endpoints.
//
// Currently "zpr-oauthrsa" is the only supported scheme and the service type of "auth"
// implies this scheme.
//
// TODO: Eventually need to expand zplc and compiler to have richer set of auth service types.
//
// Errors:
// - The only support auth serice type requires a single scope, so you get an error if there are none or more than one.
fn uri_for_service(
    skind: &ServiceType,
    addr: &IpAddr,
    endpoints: &[Scope],
) -> Result<String, VSError> {
    let scheme = match skind {
        ServiceType::Authentication => "zpr-oauthrsa",
        _ => {
            return Err(VSError::InternalError(
                format!("unsupported service type for auth service URI: {skind:?}").into(),
            ));
        }
    };

    if endpoints.len() != 1 {
        return Err(VSError::InternalError(
            format!(
                "auth service must have exactly one scope endpoint, not {}",
                endpoints.len()
            )
            .into(),
        ));
    }

    if let Some(portnum) = endpoints[0].port.as_ref() {
        let url = match addr {
            IpAddr::V4(a) => format!("{scheme}://{a}:{portnum}"),
            IpAddr::V6(a) => format!("{scheme}://[{a}]:{portnum}"),
        };
        Ok(url)
    } else {
        Err(VSError::InternalError(
            "auth service scope must have a single port defined".into(),
        ))
    }
}
