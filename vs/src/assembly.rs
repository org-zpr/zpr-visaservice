use std::sync::Arc;

use crate::actor_db::ActorDb;
use crate::connection_control::ConnectionControl;
use crate::policy_mgr::PolicyMgr;

#[allow(dead_code)]
pub struct Assembly {
    pub system_start_time: std::time::Instant,
    pub cc: ConnectionControl,
    pub policy_mgr: PolicyMgr,
    pub actor_db: ActorDb, // manages its own locking
    pub vk_conn: Arc<redis::aio::MultiplexedConnection>,
}

impl Assembly {
    #[allow(dead_code)]
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {}
}
