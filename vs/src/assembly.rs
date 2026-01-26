use std::sync::Arc;

use tokio::sync::mpsc;

use crate::actor_mgr::ActorMgr;
use crate::config::VSConfig;
use crate::connection_control::ConnectionControl;
use crate::db::DbConnection;
use crate::policy_mgr::PolicyMgr;
use crate::visa_mgr::VisaMgr;
use crate::vss_mgr::VssMgr;

#[allow(dead_code)]
pub struct Assembly {
    pub config: VSConfig,
    pub system_start_time: std::time::Instant,
    pub cc: ConnectionControl,
    pub policy_mgr: PolicyMgr,
    pub actor_mgr: Arc<ActorMgr>,
    pub state_db: Arc<dyn DbConnection>, // TODO: May not actually need this if db_handle is in all the required "managers".
    pub vreq_chan: mpsc::Sender<crate::visareq_worker::VisaRequestJob>,
    pub visa_mgr: VisaMgr,
    pub vss_mgr: VssMgr,
}

impl Assembly {
    #[allow(dead_code)]
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {}
}
