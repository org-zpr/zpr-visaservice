use std::sync::Arc;

use tokio::sync::mpsc;

use crate::actor_db::ActorDb;
use crate::connection_control::ConnectionControl;
use crate::db;
use crate::policy_mgr::PolicyMgr;
use crate::visa_mgr::VisaMgr;

#[allow(dead_code)]
pub struct Assembly {
    pub system_start_time: std::time::Instant,
    pub cc: ConnectionControl,
    pub policy_mgr: PolicyMgr,
    pub actor_db: Arc<ActorDb>,
    pub vk_conn: db::Conn,
    pub vreq_chan: mpsc::Sender<crate::visareq_worker::VisaRequestJob>,
    pub visa_mgr: VisaMgr,
}

impl Assembly {
    #[allow(dead_code)]
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {}
}
