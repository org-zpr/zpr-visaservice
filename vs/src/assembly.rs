use std::sync::Arc;

use tokio::sync::mpsc;

use crate::actor_mgr::ActorMgr;
use crate::config::VSConfig;
use crate::connection_control::ConnectionControl;
use crate::counters::Counters;
use crate::db::DbConnection;
use crate::policy_mgr::PolicyMgr;
use crate::visa_mgr::VisaMgr;
use crate::vss_mgr::VssMgr;

#[allow(dead_code)]
pub struct Assembly {
    pub config: VSConfig,
    pub counters: Counters,
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

// Note this is "pub" so other tests can use it.
#[cfg(test)]
pub mod tests {
    use super::*;

    use crate::actor_mgr::ActorMgr;
    use crate::connection_control::ConnectionControl;
    use crate::db::FakeDb;
    use crate::db::{ActorRepo, NodeRepo, PolicyRepo, VisaRepo};
    use crate::policy_mgr::PolicyMgr;
    use crate::visa_mgr::VisaMgr;
    use crate::visareq_worker::VisaRequestJob;
    use crate::vss_mgr::VssMgr;

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

    pub async fn new_assembly_for_tests(
        vreq_tx_chan: Option<mpsc::Sender<VisaRequestJob>>,
    ) -> Assembly {
        let vreq_tx = if let Some(tx) = vreq_tx_chan {
            tx
        } else {
            let (tx, _rx) = mpsc::channel(100);
            tx
        };

        let db_handle = Arc::new(FakeDb::new());

        let policy_repo = PolicyRepo::new(db_handle.clone());
        let initial_policy = make_policy("2024-01-01T00:00:00Z", 1, Some("meta"));

        let actor_repo = ActorRepo::new(db_handle.clone());
        let node_repo = NodeRepo::new(db_handle.clone());
        let visa_repo = VisaRepo::new(db_handle.clone());

        Assembly {
            config: VSConfig::default(),
            counters: Default::default(),
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
        }
    }
}
