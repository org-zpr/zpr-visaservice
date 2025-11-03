use tracing::info;

use crate::actor::Actor;
use crate::error::VSError;
use crate::logging::targets::ADB;

pub struct ActorDb {}

impl ActorDb {
    pub fn new() -> Self {
        ActorDb {}
    }

    pub fn add_node(&self, _actor: Actor) -> Result<(), VSError> {
        info!(target: ADB, "(TODO) adding node actor {}", _actor.get_cn());
        Ok(())
    }
}
