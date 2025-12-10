//! Actor manager. Manages nodes too.
//!

use libeval::actor::Actor;
use std::net::IpAddr;

use crate::db;
use crate::error::{DBError, VSError};

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
}
