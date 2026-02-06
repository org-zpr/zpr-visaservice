//! Redis/ValKey operations related to visas.
//!
//! This updates:
//! - visa:next_visa_id a counter for the next visa ID to use (actually this is set to the last visa ID handed out).
//! - visa:<ID> a hash of metadata about each visa.
//! - visas:<ID>:blob the capnp encoded visa blob itself.
//! - nodevisa:<ZADDR>:<ID> a hash of state about each visa on each node.

use capnp;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, error, warn};

use ::zpr::vsapi::v1 as vsapi;
use zpr::vsapi_types::Visa;
use zpr::write_to::WriteTo;

use crate::db::{DbConnection, DbOp, ZAddr, gen_timestamp};
use crate::error::DBError;
use crate::logging::targets::DB;

const KEY_VISA: &str = "visa";
const KEY_NEXT_VISA_ID: &str = "visa:next_visa_id";
const KEY_VISAS: &str = "visas";
const KEY_NODEVISA: &str = "nodevisa";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeVisaState {
    PendingInstall,
    Installed,
    PendingRevoke,
    Revoked,
}

pub struct VisaRepo {
    db: Arc<dyn DbConnection>,
}

impl VisaRepo {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        // TODO: Could sanity check db state here.
        VisaRepo { db }
    }

    pub async fn get_next_visa_id(&self) -> Result<u64, DBError> {
        let next_id: u64 = self.db.incr(KEY_NEXT_VISA_ID, 1).await?;
        Ok(next_id)
    }

    /// Remove references to a visa from the state datbase. Caller must make sure
    /// that any revocation messages or whatever have already been sent.
    async fn clean_up(&self, visa_id: u64) -> Result<(), DBError> {
        let blob_key = blob_key_for_visa(visa_id);
        let visa_id_key = visa_key_for_visa(visa_id);

        let ops = vec![DbOp::Del(blob_key.clone()), DbOp::Del(visa_id_key.clone())];
        self.db.atomic_pipeline(&ops).await?;

        // Remove any nodevisa references to this visa.
        let nodevisa_keys = self
            .db
            .scan_match_all(format!("{KEY_NODEVISA}:*:{visa_id}"))
            .await?;
        if !nodevisa_keys.is_empty() {
            let ops = nodevisa_keys
                .iter()
                .map(|k| DbOp::Del(k.clone()))
                .collect::<Vec<DbOp>>();
            self.db.atomic_pipeline(&ops).await?;
        }
        Ok(())
    }

    /// Force remove all the nodevisa:<ZADDR>:<ID> tables that refer to the
    /// passed `node_addr`.
    ///
    /// Does not remove visa:* entries.
    ///
    /// TODO: A future version may remove the visa:ID entries so long as they
    /// are not referenced on another node.
    ///
    pub async fn clear_node_state(&self, node_addr: &IpAddr) -> Result<(), DBError> {
        let zaddr = ZAddr::from(node_addr);
        let nodevisa_keys = self
            .db
            .scan_match_all(format!("{KEY_NODEVISA}:{zaddr}:*"))
            .await?;
        if !nodevisa_keys.is_empty() {
            let ops = nodevisa_keys
                .iter()
                .map(|k| DbOp::Del(k.clone()))
                .collect::<Vec<DbOp>>();
            self.db.atomic_pipeline(&ops).await?;
        }
        Ok(())
    }

    /// Store a new visa in the database, also sets the visa state with respect to the requesting node as
    /// `nstate`.
    ///
    /// TODO: We may want to code path that does not include a requesting node.
    ///
    pub async fn store_visa(
        &self,
        requesting_node: &IpAddr,
        visa: &Visa,
        nstate: NodeVisaState,
    ) -> Result<(), DBError> {
        match self.try_store_visa(requesting_node, visa, nstate).await {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!(target: DB, "failed to store visa: {}, attempting cleanup", visa.issuer_id);
                match self.clean_up(visa.issuer_id).await {
                    Ok(_) => (),
                    Err(cleanup_err) => {
                        error!(target: DB, "failed to store visa {} and clean up failed too: {}", visa.issuer_id, cleanup_err);
                    }
                }
                Err(e)
            }
        }
    }

    /// Attempt to store a visa.
    ///
    /// Will set the state w/ respect to the requesting_node to the passed `nstate`. Normally
    /// this should be [NodeVisaState::PendingInstall] but there are occasions where you may
    /// want to set it as [NodeVisaState::Installed].
    async fn try_store_visa(
        &self,
        requesting_node: &IpAddr,
        visa: &Visa,
        nstate: NodeVisaState,
    ) -> Result<(), DBError> {
        // write capnpn version of visa into the store.

        let visa_id = visa.issuer_id;

        let expiration_seconds = seconds_until(visa.expires);
        if expiration_seconds == 0 {
            return Err(DBError::InvalidData(
                "attempt to store already expired visa".into(),
            ));
        }

        // Store the whole visa in there in capnp format
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut visa_bldr = msg.init_root::<vsapi::visa::Builder>();
            visa.write_to(&mut visa_bldr);
            // Ends up dropping the visa_bldr and forgetting the mut borrow of msg.
        }
        let mut words: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut words, &msg)?;

        //
        // visa:<ID>:blob -> <capn proto bytes>
        //
        self.db
            .set_bin_ex(&blob_key_for_visa(visa_id), &words, expiration_seconds)
            .await?;

        let key_visa = visa_key_for_visa(visa_id);

        //
        // visa:<ID>
        //       |- requesting_node -> string, zpr address
        //       |- ctime           -> string, timestamp
        //
        self.db
            .hset_multiple(
                &key_visa,
                &[
                    ("requesting_node", requesting_node.to_string().as_str()),
                    ("ctime", &gen_timestamp()),
                ],
            )
            .await?;
        self.db.expire(&key_visa, expiration_seconds as i64).await?;

        //
        // nodevisa:<ZADDR>:<ID>
        //                   |- state -> string, JSON serialized NodeVisaState
        //                   |- utime -> string, timestamp
        //

        // TODO: We may want to use a struct here for the whole state entry and just serialize it all
        // as JSON, but for now am leaving open option of just updating fields individually using redis.
        let key_nodevisa = node_visa_key_for_visa(requesting_node, visa_id);
        self.db
            .hset_multiple(
                &key_nodevisa,
                &[
                    ("state", &serde_json::to_string(&nstate)?),
                    ("utime", &gen_timestamp()),
                ],
            )
            .await?;
        self.db
            .expire(&key_nodevisa, expiration_seconds as i64)
            .await?;

        debug!(target: DB, "stored visa {visa_id} expires in {expiration_seconds} seconds");
        Ok(())
    }

    /// Update the nodevisa state information for the node and visa.
    pub async fn update_node_visa_state(
        &self,
        node_addr: &IpAddr,
        visa_id: u64,
        new_state: NodeVisaState,
    ) -> Result<(), DBError> {
        let key_nodevisa = node_visa_key_for_visa(node_addr, visa_id);
        if !self.db.exists(&key_nodevisa).await? {
            return Err(DBError::NotFound(format!(
                "node-visa record not found: {key_nodevisa}"
            )));
        }
        self.db
            .hset_multiple(
                &key_nodevisa,
                &[
                    ("state", &serde_json::to_string(&new_state)?),
                    ("last_update", &gen_timestamp()),
                ],
            )
            .await?;

        debug!(target: DB, "updated nodevisa state node={node_addr} visa={visa_id} -> {new_state:?}");
        Ok(())
    }

    /// Expired visas will have been removed from redis, so if we find any empty
    /// keys they are just skipped.
    pub async fn get_visas_for_node_by_state(
        &self,
        node_addr: &IpAddr,
        state: NodeVisaState,
    ) -> Result<Vec<Visa>, DBError> {
        let zaddr = ZAddr::from(node_addr);
        let mut visas = Vec::new();

        let vkeys = self
            .db
            .scan_match_all(format!("{KEY_NODEVISA}:{zaddr}:*"))
            .await?;

        for key in &vkeys {
            let state_str: String = self.db.hget(&key, "state").await?.unwrap_or_default();
            let entry_state: NodeVisaState = serde_json::from_str(&state_str)?;
            if entry_state == state {
                // Extract visa ID from key
                let parts: Vec<&str> = key.rsplitn(2, ':').collect();
                if parts.len() != 2 {
                    warn!(target: DB, "malformed nodevisa key: {}", key);
                    continue;
                }
                let visa_id: u64 = parts[0].parse().map_err(|_| {
                    DBError::InvalidData(format!("invalid visa ID in nodevisa key: {}", key))
                })?;

                // Load the visa blob
                let blob_key = blob_key_for_visa(visa_id);
                match self.db.get_bin(&blob_key).await {
                    Ok(visa_blob) => {
                        let visa = Visa::from_capnp_bytes(&visa_blob)?;
                        visas.push(visa);
                    }
                    Err(err) if err.kind() == redis::ErrorKind::UnexpectedReturnType => {
                        // Missing/expired visa blob. Skip it but keep other visas.
                        warn!(target: DB, "visa blob missing for key {}", blob_key);
                        continue;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }

        Ok(visas)
    }

    /// Copy all the visa IDs into a vec.
    pub async fn list_visa_ids(&self) -> Result<Vec<u64>, DBError> {
        let visa_keys = self.db.scan_match_all(format!("{KEY_VISA}:[0-9]*")).await?;
        let mut visa_ids = Vec::new();
        for key in &visa_keys {
            let parts: Vec<&str> = key.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                warn!(target: DB, "malformed visa key: {}", key);
                continue;
            }
            let visa_id: u64 = match parts[0].parse() {
                Err(_) => {
                    // TODO: Should we just crash here?
                    warn!(target: DB, "invalid visa ID in visa key: {}, skipping entry", key);
                    continue;
                }
                Ok(id) => id,
            };
            visa_ids.push(visa_id);
        }
        Ok(visa_ids)
    }
}

// Get number of seconds until the given SystemTime or zero if in the past.
fn seconds_until(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn blob_key_for_visa(visa_id: u64) -> String {
    format!("{KEY_VISAS}:{visa_id}:blob")
}

fn visa_key_for_visa(visa_id: u64) -> String {
    format!("{KEY_VISA}:{visa_id}")
}

fn node_visa_key_for_visa(node_addr: &IpAddr, visa_id: u64) -> String {
    let zaddr = ZAddr::from(node_addr);
    format!("{KEY_NODEVISA}:{zaddr}:{visa_id}")
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::DbConnection;
    use crate::db::db_fake::FakeDb;
    use std::time::SystemTime;
    use zpr::vsapi_types::{DockPep, EndpointT, KeySet, TcpUdpPep};

    fn make_visa(visa_id: u64, expires_in: Duration) -> Visa {
        Visa::new(
            visa_id,
            0,
            SystemTime::now() + expires_in,
            "fd5a:5052::10".parse().unwrap(),
            "fd5a:5052::20".parse().unwrap(),
            DockPep::TCP(TcpUdpPep::new(1234, 443, EndpointT::Server)),
            KeySet::new(b"ingress", b"egress"),
            None,
        )
    }

    #[tokio::test]
    async fn test_store_and_get_visas_by_state() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone());
        let node_addr: IpAddr = "fd5a:5052::1".parse().unwrap();
        let visa = make_visa(42, Duration::from_secs(60));

        repo.store_visa(&node_addr, &visa, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        assert!(db.exists(&blob_key_for_visa(42)).await.unwrap());
        assert!(db.exists(&visa_key_for_visa(42)).await.unwrap());
        assert!(
            db.exists(&node_visa_key_for_visa(&node_addr, 42))
                .await
                .unwrap()
        );

        let pending = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].issuer_id, 42);

        repo.update_node_visa_state(&node_addr, 42, NodeVisaState::Installed)
            .await
            .unwrap();
        let pending = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert!(pending.is_empty());

        let installed = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::Installed)
            .await
            .unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].issuer_id, 42);
    }

    #[tokio::test]
    async fn test_update_node_visa_state_missing() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db);
        let node_addr: IpAddr = "fd5a:5052::2".parse().unwrap();

        let err = repo
            .update_node_visa_state(&node_addr, 99, NodeVisaState::Installed)
            .await
            .unwrap_err();
        match err {
            DBError::NotFound(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_clear_node_state_only_removes_nodevisa() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone());
        let node_addr: IpAddr = "fd5a:5052::3".parse().unwrap();
        let visa = make_visa(7, Duration::from_secs(60));

        repo.store_visa(&node_addr, &visa, NodeVisaState::Installed)
            .await
            .unwrap();

        repo.clear_node_state(&node_addr).await.unwrap();

        assert!(
            !db.exists(&node_visa_key_for_visa(&node_addr, 7))
                .await
                .unwrap()
        );
        assert!(db.exists(&blob_key_for_visa(7)).await.unwrap());
        assert!(db.exists(&visa_key_for_visa(7)).await.unwrap());
    }

    #[tokio::test]
    async fn test_store_visa_rejects_expired() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db);
        let node_addr: IpAddr = "fd5a:5052::4".parse().unwrap();
        let mut visa = make_visa(8, Duration::from_secs(1));
        visa.expires = SystemTime::now() - Duration::from_secs(1);

        let err = repo
            .store_visa(&node_addr, &visa, NodeVisaState::PendingInstall)
            .await
            .unwrap_err();
        match err {
            DBError::InvalidData(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_update_node_visa_state_after_expiry() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db);
        let node_addr: IpAddr = "fd5a:5052::5".parse().unwrap();
        let visa = make_visa(9, Duration::from_secs(5));

        repo.store_visa(&node_addr, &visa, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        tokio::time::advance(Duration::from_secs(6)).await;

        let err = repo
            .update_node_visa_state(&node_addr, 9, NodeVisaState::Installed)
            .await
            .unwrap_err();
        match err {
            DBError::NotFound(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_visas_skips_missing_blobs() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db.clone());
        let node_addr: IpAddr = "fd5a:5052::6".parse().unwrap();
        let visa_a = make_visa(10, Duration::from_secs(60));
        let visa_b = make_visa(11, Duration::from_secs(60));

        repo.store_visa(&node_addr, &visa_a, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        repo.store_visa(&node_addr, &visa_b, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        db.del(&blob_key_for_visa(10)).await.unwrap();

        let visas = repo
            .get_visas_for_node_by_state(&node_addr, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        assert_eq!(visas.len(), 1);
        assert_eq!(visas[0].issuer_id, 11);
    }

    #[tokio::test]
    async fn test_list_visa_ids_after_store() {
        let db = Arc::new(FakeDb::new());
        let repo = VisaRepo::new(db);
        let node_addr: IpAddr = "fd5a:5052::7".parse().unwrap();

        let visa_a = make_visa(1, Duration::from_secs(60));
        let visa_b = make_visa(5, Duration::from_secs(60));
        let visa_c = make_visa(42, Duration::from_secs(60));

        repo.store_visa(&node_addr, &visa_a, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        repo.store_visa(&node_addr, &visa_b, NodeVisaState::PendingInstall)
            .await
            .unwrap();
        repo.store_visa(&node_addr, &visa_c, NodeVisaState::PendingInstall)
            .await
            .unwrap();

        let mut ids = repo.list_visa_ids().await.unwrap();
        ids.sort_unstable();

        assert_eq!(ids, vec![1, 5, 42]);
    }
}
