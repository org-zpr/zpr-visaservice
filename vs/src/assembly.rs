use std::sync::Arc;
use std::sync::RwLock;

use crate::actor_db::ActorDb;
use crate::connection_control::ConnectionControl;
use crate::policy::Policy;

#[allow(dead_code)]
pub struct Assembly {
    pub system_start_time: std::time::Instant,
    pub cc: ConnectionControl,
    pub policy: RwLock<Policy>,
    pub actor_db: ActorDb, // manages its own locking
}

impl Assembly {
    pub fn new() -> Self {
        Assembly {
            system_start_time: std::time::Instant::now(),
            cc: ConnectionControl::new(),
            policy: RwLock::new(Policy::new_empty()),
            actor_db: ActorDb::new(),
        }
    }

    #[allow(dead_code)]
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {}
}
