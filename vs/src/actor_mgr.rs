//! Actor manager. Manages nodes too.
//!

use libeval::actor::Actor;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use zpr::policy_types::{Scope, ServiceType};
use zpr::vsapi_types::ServiceDescriptor;

use crate::assembly::Assembly;
use crate::db;
use crate::error::{ServiceError, StoreError};

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
    pub async fn add_node(&self, actor: &Actor) -> Result<(), ServiceError> {
        if !actor.is_node() {
            return Err(ServiceError::Internal(
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
    pub async fn remove_node(&self, node_addr: &IpAddr) -> Result<(), ServiceError> {
        self.node_db.remove_node(node_addr).await?;
        Ok(())
    }

    /// Update vss socket for given node in the DB.
    pub async fn set_node_vss(&self, node_addr: &IpAddr, vss: &SocketAddr) -> Result<(), ServiceError> {
        self.node_db.set_node_vss(node_addr, vss).await?;
        Ok(())
    }

    /// Add an adatpter called "magic" since it is not connected to any node.
    /// We (the visa service) uses this to connect itself at startup.
    ///
    /// TODO: At some point we need to update our state to reflect that the visa service is docked to a node.
    pub async fn add_magic_adapter(&self, actor: &Actor) -> Result<(), ServiceError> {
        if actor.is_node() {
            return Err(ServiceError::Internal(
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
    ) -> Result<(), ServiceError> {
        if actor.is_node() {
            return Err(ServiceError::Internal(
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
    pub async fn get_actor_by_zpr_addr(&self, zpra: &IpAddr) -> Result<Option<Actor>, ServiceError> {
        match self.actor_db.get_actor_by_zpr_addr(zpra).await {
            Ok(actor) => Ok(Some(actor)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(ServiceError::from(e)),
        }
    }

    /// Remove actor state from the database. If removing a node, also call [ActorMgr::remove_node].
    pub async fn remove_actor_by_zpr_addr(&self, zpra: &IpAddr) -> Result<(), ServiceError> {
        Ok(self.actor_db.rm_actor_by_zpr_addr(zpra).await?)
    }

    /// Returns ZPR addresses of adapters (NOT nodes) connected to the given node.
    pub async fn get_adapters_connected_to_node(
        &self,
        node_addr: &IpAddr,
    ) -> Result<Vec<IpAddr>, ServiceError> {
        Ok(self
            .node_db
            .get_connected_adapters(node_addr)
            .await?
            .into_iter()
            .collect())
    }

    /// Get the list of connected authentication services.
    pub async fn get_auth_services_list(
        &self,
        asm: Arc<Assembly>,
    ) -> Result<Vec<ServiceDescriptor>, ServiceError> {
        let mut services = Vec::new();

        // From the DB we can get the (service_name, zpr_addr) for each connected service.
        let service_entries = self.actor_db.list_services().await?;

        // Then we need to consult policy to get the service details.
        let pol = asm.policy_mgr.get_current();

        let mut svc_map = HashMap::new();
        for svc in pol.list_services_by_kind(ServiceType::Authentication) {
            svc_map.insert(svc.id.clone(), svc);
        }

        if !svc_map.is_empty() {
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
                }
            }
        }

        Ok(services)
    }

    /// Get the list of connectioned actor CN values, optionally filtered by role.
    pub async fn list_actor_cns(&self, by_role: Option<db::Role>) -> Result<Vec<String>, ServiceError> {
        let cns = self.actor_db.list_actor_cns(by_role).await?;
        Ok(cns)
    }
}

// The auth service URI is of the form: <ZPR_AUTH_SCHEME>://<addr>:<port>/path
//
// Example: 'zpr-oauthrsa://[fd5a:5052:9090::88]:4000'
//
// The 'zpr-oauthrsa' scheme implies "https" and "/preauthorize" and "/authorize" endpoints.
//
// Currently "zpr-oauthrsa" is the only supported scheme and the service type of "auth"
// implies this scheme.
//
// TODO: Eventually we need to expand zplc and the compiler to have richer set of
// auth service types.
//
// TODO: The ph is passing the ASA info to the adapters as a socket-addr and the
// mechanics of zpr-oauthrsa are built in or something.  This all needs a clean up.
//
// Errors:
// - The only supported auth serice type requires a single scope, so you get an error
//   if there are none or more than one.
fn uri_for_service(
    skind: &ServiceType,
    addr: &IpAddr,
    endpoints: &[Scope],
) -> Result<String, ServiceError> {
    let scheme = match skind {
        ServiceType::Authentication => "zpr-oauthrsa",
        _ => {
            return Err(ServiceError::Internal(
                format!("unsupported service type for auth service URI: {skind:?}").into(),
            ));
        }
    };

    if endpoints.len() != 1 {
        return Err(ServiceError::Internal(
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
        Err(ServiceError::Internal(
            "auth service scope must have a single port defined".into(),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::{ActorRepo, FakeDb, NodeRepo};
    use crate::test_helpers::{make_adapter_actor_defexp, make_node_actor_defexp};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    fn make_mgr() -> ActorMgr {
        let db = Arc::new(FakeDb::new());
        let actor_repo = ActorRepo::new(db.clone());
        let node_repo = NodeRepo::new(db);
        ActorMgr::new(actor_repo, node_repo)
    }

    #[tokio::test]
    async fn test_add_node_and_set_vss() {
        let mgr = make_mgr();
        let actor = make_node_actor_defexp("fd5a:5052::1", "node-1", "[fd5a:5052::100]:1234");
        let node_addr: IpAddr = "fd5a:5052::1".parse().unwrap();

        mgr.add_node(&actor).await.unwrap();
        let loaded = mgr.get_actor_by_zpr_addr(&node_addr).await.unwrap();
        assert!(matches!(loaded, Some(a) if a.is_node()));

        let vss_addr: SocketAddr = "[fd5a:5052::200]:4000".parse().unwrap();
        mgr.set_node_vss(&node_addr, &vss_addr).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_node_rejects_non_node() {
        let mgr = make_mgr();
        let actor = make_adapter_actor_defexp("fd5a:5052::2", "adapter-1");

        let err = mgr.add_node(&actor).await.unwrap_err();
        match err {
            ServiceError::Internal(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_actor_by_zpr_addr_none() {
        let mgr = make_mgr();
        let addr: IpAddr = "fd5a:5052::3".parse().unwrap();

        let result = mgr.get_actor_by_zpr_addr(&addr).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_add_adapter_via_node_tracks_connections() {
        let mgr = make_mgr();
        let node_actor = make_node_actor_defexp("fd5a:5052::4", "node-2", "[fd5a:5052::101]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::5", "adapter-2");
        let node_addr: IpAddr = "fd5a:5052::4".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::5".parse().unwrap();

        mgr.add_node(&node_actor).await.unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr)
            .await
            .unwrap();

        let adapters = mgr
            .get_adapters_connected_to_node(&node_addr)
            .await
            .unwrap();
        assert!(adapters.contains(&adapter_addr));

        let loaded = mgr.get_actor_by_zpr_addr(&adapter_addr).await.unwrap();
        assert!(matches!(loaded, Some(a) if !a.is_node()));
    }

    #[tokio::test]
    async fn test_remove_actor_by_zpr_addr() {
        let mgr = make_mgr();
        let node_actor = make_node_actor_defexp("fd5a:5052::6", "node-3", "[fd5a:5052::102]:1234");
        let adapter_actor = make_adapter_actor_defexp("fd5a:5052::7", "adapter-3");
        let node_addr: IpAddr = "fd5a:5052::6".parse().unwrap();
        let adapter_addr: IpAddr = "fd5a:5052::7".parse().unwrap();

        mgr.add_node(&node_actor).await.unwrap();
        mgr.add_adapter_via_node(&adapter_actor, &node_addr)
            .await
            .unwrap();

        mgr.remove_actor_by_zpr_addr(&adapter_addr).await.unwrap();
        let loaded = mgr.get_actor_by_zpr_addr(&adapter_addr).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_set_node_vss_missing_node() {
        let mgr = make_mgr();
        let node_addr: IpAddr = "fd5a:5052::8".parse().unwrap();
        let vss_addr: SocketAddr = "[fd5a:5052::201]:4000".parse().unwrap();

        let err = mgr.set_node_vss(&node_addr, &vss_addr).await.unwrap_err();
        match err {
            ServiceError::Store(StoreError::NotFound(_)) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_uri_for_service_ipv6_auth() {
        let addr: IpAddr = "fd5a:5052::9".parse().unwrap();
        let endpoints = [Scope {
            protocol: 0,
            flag: None,
            port: Some(4000),
            port_range: None,
        }];

        let uri = uri_for_service(&ServiceType::Authentication, &addr, &endpoints).unwrap();
        assert_eq!(uri, "zpr-oauthrsa://[fd5a:5052::9]:4000");
    }

    #[test]
    fn test_uri_for_service_errors() {
        let addr: IpAddr = "fd5a:5052::10".parse().unwrap();
        let endpoints = [Scope {
            protocol: 0,
            flag: None,
            port: Some(4000),
            port_range: None,
        }];

        let err = uri_for_service(&ServiceType::Regular, &addr, &endpoints).unwrap_err();
        match err {
            ServiceError::Internal(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }

        let err = uri_for_service(&ServiceType::Authentication, &addr, &[]).unwrap_err();
        match err {
            ServiceError::Internal(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }

        let endpoints_missing_port = [Scope {
            protocol: 0,
            flag: None,
            port: None,
            port_range: None,
        }];
        let err = uri_for_service(&ServiceType::Authentication, &addr, &endpoints_missing_port)
            .unwrap_err();
        match err {
            ServiceError::Internal(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
