//! Actor Database will eventually be backed by ValKey.
//! This will know all the connected actors, their addresses, the services the offer, etc.
//! Including all nodes and links between them.

use tracing::info;

use libeval::actor::Actor;

use crate::error::VSError;
use crate::logging::targets::ADB;

pub struct ActorDb {}

impl ActorDb {
    pub fn new() -> Self {
        ActorDb {}
    }

    pub fn add_node(&self, _actor: Actor) -> Result<(), VSError> {
        info!(target: ADB, "(TODO) adding node actor {:?}", _actor.get_cn());
        Ok(())
    }
}
