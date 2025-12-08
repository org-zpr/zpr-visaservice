//! Actor Database will eventually be backed by ValKey.
//! This will know all the connected actors, their addresses, the services the offer, etc.
//! Including all nodes and links between them.

use libeval::actor::Actor;
use std::net::IpAddr;

use crate::db;
use crate::error::{DBError, VSError};

pub struct ActorMgr {
    db: db::ActorRepo,
}

impl ActorMgr {
    pub fn new(repo: db::ActorRepo) -> Self {
        ActorMgr { db: repo }
    }

    pub async fn add_node(&self, actor: Actor) -> Result<(), VSError> {
        if !actor.is_node() {
            return Err(VSError::InternalError(
                "attempt to add non-node actor as node".into(),
            ));
        }
        Ok(self.db.add_actor(actor).await?)
    }

    pub async fn add_adapter(&self, actor: Actor) -> Result<(), VSError> {
        if actor.is_node() {
            return Err(VSError::InternalError(
                "attempt to add node actor as adapter".into(),
            ));
        }
        Ok(self.db.add_actor(actor).await?)
    }

    /// Returns Ok(None) if not found.
    pub async fn get_actor_by_zpr_addr(&self, zpra: &IpAddr) -> Result<Option<Actor>, VSError> {
        match self.db.get_actor_by_zpr_addr(zpra).await {
            Ok(actor) => Ok(Some(actor)),
            Err(DBError::NotFound(_)) => Ok(None),
            Err(e) => Err(VSError::from(e)),
        }
    }

    pub async fn remove_actor_by_zpr_addr(&self, zpra: &IpAddr) -> Result<(), VSError> {
        Ok(self.db.rm_actor_by_zpr_addr(zpra).await?)
    }
}
