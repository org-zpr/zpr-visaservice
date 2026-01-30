use std::sync::{Arc, RwLock};

use tokio::sync::mpsc;

use crate::actor_mgr::ActorMgr;
use crate::config::VSConfig;
use crate::connection_control::ConnectionControl;
use crate::db::DbConnection;
use crate::net_mgr::NetMgr;
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
    pub net_mgr: Arc<RwLock<NetMgr>>,
}

impl Assembly {
    #[allow(dead_code)]
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {}
}

// Note this is "pub" so other tests can use it.
#[cfg(test)]
pub mod tests {
    use super::*;

    use crate::actor_mgr::ActorMgr;
    use crate::connection_control::ConnectionControl;
    use crate::policy_mgr::PolicyMgr;
    use crate::visa_mgr::VisaMgr;
    use crate::vss_mgr::VssMgr;

    use crate::db::FakeDb;
    use crate::db::{ActorRepo, NodeRepo, PolicyRepo, VisaRepo};

    use bytes::Bytes;
    use libeval::policy::Policy;
    use zpr::policy::v1;

    fn make_policy(created: &str, version: u64, metadata: Option<&str>) -> Policy {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<v1::policy::Builder>();
            policy_bldr.set_created(created);
            policy_bldr.set_version(version);
            if let Some(md) = metadata {
                policy_bldr.set_metadata(md);
            } else {
                policy_bldr.set_metadata("");
            }
        }
        let mut bytes = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        Policy::new_from_policy_bytes(Bytes::copy_from_slice(&bytes)).unwrap()
    }

    pub async fn new_assembly_for_tests() -> Assembly {
        let (vreq_tx, _vreq_rx) = mpsc::channel(100);

        let db_handle = Arc::new(FakeDb::new());

        let policy_repo = PolicyRepo::new(db_handle.clone());
        let initial_policy = make_policy("2024-01-01T00:00:00Z", 1, Some("meta"));

        let actor_repo = ActorRepo::new(db_handle.clone());
        let node_repo = NodeRepo::new(db_handle.clone());
        let visa_repo = VisaRepo::new(db_handle.clone());

        Assembly {
            config: VSConfig::default(),
            system_start_time: std::time::Instant::now(),
            cc: ConnectionControl::new(),
            policy_mgr: PolicyMgr::new_with_initial_policy(initial_policy, policy_repo)
                .await
                .expect("failed to initialize PolicyMgr"),
            actor_mgr: Arc::new(ActorMgr::new(actor_repo, node_repo)),
            state_db: db_handle,
            vreq_chan: vreq_tx,
            visa_mgr: VisaMgr::new(visa_repo),
            vss_mgr: VssMgr::new(),
            net_mgr: Arc::new(RwLock::new(
                NetMgr::new().await.expect("failed to create NetMgr"),
            )),
        }
    }
}
