//! Actor Database will eventually be backed by ValKey.
//! This will know all the connected actors, their addresses, the services the offer, etc.
//! Including all nodes and links between them.

use std::collections::HashMap;
use std::sync::RwLock;
use tracing::debug;

use libeval::actor::Actor;

use crate::error::VSError;
use crate::logging::targets::ADB;

pub struct ActorDb {
    db: RwLock<Tables>,
}

struct Tables {
    actors: HashMap<String, Actor>,                // ident -> actor
    addr_index: HashMap<std::net::IpAddr, String>, // zpr_addr -> ident
}

impl ActorDb {
    pub fn new() -> Self {
        ActorDb {
            db: RwLock::new(Tables {
                actors: HashMap::new(),
                addr_index: HashMap::new(),
            }),
        }
    }

    pub fn add_node(&self, actor: Actor) -> Result<(), VSError> {
        if !actor.is_node() {
            return Err(VSError::InternalError(
                "attempt to add non-node actor as node".into(),
            ));
        }
        self.add_actor(actor)
    }

    pub fn add_adapter(&self, actor: Actor) -> Result<(), VSError> {
        if actor.is_node() {
            return Err(VSError::InternalError(
                "attempt to add node actor as adapter".into(),
            ));
        }
        self.add_actor(actor)
    }

    pub fn remove_actor_by_zpr_addr(&self, zpra: &std::net::IpAddr) -> Result<(), VSError> {
        let mut self_db = self
            .db
            .write()
            .map_err(|e| VSError::InternalError(format!("ActorDb lock poisoned: {}", e)))?;
        if let Some(ident) = self_db.addr_index.remove(zpra) {
            debug!(target: ADB, "removing actor from DB: ident={ident} zpr_addr={zpra}");
            self_db.actors.remove(&ident);
        } else {
            debug!(target: ADB, "actor not found in addr index: {zpra}");
        }
        Ok(())
    }

    fn add_actor(&self, actor: Actor) -> Result<(), VSError> {
        let idents = actor.get_identity().ok_or(VSError::InternalError(
            "attempt to store an actor with no identity".into(),
        ))?;
        let ident = idents.join(":");

        let maybe_zpraddr = match actor.get_zpr_addr() {
            Some(addr) => Some(addr.clone()),
            None => None,
        };
        debug!(target: ADB, "Adding actor to DB: cn={:?} ident={ident}", actor.get_cn());

        let mut self_db = self
            .db
            .write()
            .map_err(|e| VSError::InternalError(format!("ActorDb lock poisoned: {}", e)))?;
        self_db.actors.insert(ident.clone(), actor);
        if let Some(zpraddr) = maybe_zpraddr {
            self_db.addr_index.insert(zpraddr.clone(), ident.clone());
        }
        Ok(())
    }

    /// Look up actor by ZPR address. Returns a copy of the actor if found.
    pub fn get_actor_by_zpr_addr(&self, zpra: &std::net::IpAddr) -> Option<Actor> {
        let self_db = self.db.read().ok()?;
        if let Some(ident) = self_db.addr_index.get(zpra) {
            if let Some(actor) = self_db.actors.get(ident) {
                return Some(actor.clone());
            }
        }
        None
    }
}
