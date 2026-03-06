//! Redis/ValKey operations related to policy.
//!
//! PHASH is a hash of the policy. Should change if the policy changes or is recompiled.
//!
//! This updates:
//! - policies:<PHASH>:blob maps to a raw string value which is capn proto encoded bytes of the policy.
//! - policy:current a hash which includes key 'phash' with the current policy PHASH.
//!

use libeval::policy::Policy;
use openssl::hash::{Hasher, MessageDigest};
use std::sync::Arc;
use tracing::debug;

use crate::db;
use crate::db::{DbConnection, DbOp};
use crate::error::StoreError;
use crate::logging::targets::DB;

const KEY_POLICIES: &str = "policies";
const KEY_POLICY: &str = "policy";

pub struct PolicyRepo {
    db: Arc<dyn DbConnection>,
}

impl PolicyRepo {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        PolicyRepo { db }
    }

    /// Set the current policy information into the database.
    /// Unless `force_overwrite` is true, only updates the database if the current
    /// policy is different (by its phash) from the one already stored.
    ///
    /// Return TRUE only if database was written to.
    pub async fn set_current_policy(
        &self,
        policy: &Policy,
        force_overwrite: bool,
    ) -> Result<bool, StoreError> {
        let phash = hash_for_policy(policy)?;
        let maybe_curhash: Option<String> = self.db.hget("policy:current", "phash").await?;
        let curhash = maybe_curhash.unwrap_or_default();
        let exists: bool = (curhash == phash)
            && self
                .db
                .exists(&format!("{KEY_POLICIES}:{phash}:blob"))
                .await?;
        let mut updated = false;
        if !exists || force_overwrite {
            debug!(target: DB, "updating current policy in DB to phash {phash}");
            let pbuf = policy.get_serialized(); // get capn proto bytes

            //
            // policies:<PHASH>:blob -> <capn proto bytes>
            //
            self.db
                .set_bin(&format!("{KEY_POLICIES}:{phash}:blob"), pbuf.as_ref())
                .await?;

            let key_current = format!("{KEY_POLICY}:current");

            //
            // policy:current
            //          |- phash -> the string <PHASH> value
            //          |- ctime -> string
            //
            let ops = vec![
                DbOp::HSet {
                    hash_key: key_current.clone(),
                    field: "phash".to_string(),
                    value: phash.clone(),
                },
                DbOp::HSet {
                    hash_key: key_current.clone(),
                    field: "ctime".to_string(),
                    value: db::gen_timestamp(),
                },
            ];
            self.db.atomic_pipeline(&ops).await?;

            updated = true;
        } else {
            debug!(target: DB, "set_current_policy found policy already set, hash={phash}");
        }

        Ok(updated)
    }

    /// Load the current policy stored in the database. This will return an error if there is no current policy set, or if the
    /// current policy blob cannot be deserialized into a Policy struct.
    pub async fn get_current_policy(&self) -> Result<Policy, StoreError> {
        let maybe_curhash: Option<String> = self.db.hget("policy:current", "phash").await?;
        let curhash =
            maybe_curhash.ok_or_else(|| StoreError::NotFound("no current policy set".into()))?;
        let blob_key = format!("{KEY_POLICIES}:{curhash}:blob");
        let pbytes = self.db.get_bin(&blob_key).await?;
        match Policy::new_from_policy_bytes(pbytes.into()) {
            Ok(p) => Ok(p),
            Err(e) => Err(StoreError::InvalidData(format!(
                "failed to de-serialize policy: {e}"
            ))),
        }
    }
}

fn hash_for_policy(policy: &Policy) -> Result<String, StoreError> {
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    if let Some(ctimestr) = policy.get_created() {
        hasher.update(ctimestr.as_bytes())?;
    } else {
        return Err(StoreError::MissingRequired("created timestamp".to_string()));
    }
    if let Some(version) = policy.get_version() {
        hasher.update(&version.to_be_bytes())?;
    } else {
        return Err(StoreError::MissingRequired("version".to_string()));
    }
    if let Some(md) = policy.get_metadata() {
        hasher.update(md.as_bytes())?;
    }
    let dig = hasher.finish()?;

    let phash = hex::encode(dig);
    Ok(phash)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::db_fake::FakeDb;
    use bytes::Bytes;
    use std::time::Duration;
    use zpr::policy::v1 as policy_capnp;

    fn make_policy(created: &str, version: u64, metadata: Option<&str>) -> Policy {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy_bldr = msg.init_root::<policy_capnp::policy::Builder>();
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

    #[tokio::test]
    async fn test_set_current_policy_initial_write() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db.clone());
        let policy = make_policy("2024-01-01T00:00:00Z", 1, Some("meta"));

        let updated = repo.set_current_policy(&policy, false).await.unwrap();
        assert!(updated);

        let phash = db.hget("policy:current", "phash").await.unwrap().unwrap();
        let blob_key = format!("{KEY_POLICIES}:{phash}:blob");
        let stored = db.get_bin(&blob_key).await.unwrap();
        assert_eq!(stored, policy.get_serialized().as_ref());
    }

    #[tokio::test]
    async fn test_set_current_policy_no_change() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        let policy = make_policy("2024-01-01T00:00:00Z", 2, Some("meta"));

        let updated = repo.set_current_policy(&policy, false).await.unwrap();
        assert!(updated);
        let updated = repo.set_current_policy(&policy, false).await.unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    async fn test_set_current_policy_force_overwrite() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        let policy = make_policy("2024-01-01T00:00:00Z", 3, Some("meta"));

        let updated = repo.set_current_policy(&policy, false).await.unwrap();
        assert!(updated);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let updated = repo.set_current_policy(&policy, true).await.unwrap();
        assert!(updated);
    }

    #[tokio::test]
    async fn test_set_current_policy_missing_fields() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db);
        let policy = Policy::new_empty();

        let err = repo.set_current_policy(&policy, false).await.unwrap_err();
        match err {
            StoreError::MissingRequired(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_set_current_policy_rewrites_when_blob_missing() {
        let db = Arc::new(FakeDb::new());
        let repo = PolicyRepo::new(db.clone());
        let policy = make_policy("2024-01-01T00:00:00Z", 4, Some("meta"));

        let updated = repo.set_current_policy(&policy, false).await.unwrap();
        assert!(updated);

        let phash = db.hget("policy:current", "phash").await.unwrap().unwrap();
        db.del(&format!("{KEY_POLICIES}:{phash}:blob"))
            .await
            .unwrap();

        let updated = repo.set_current_policy(&policy, false).await.unwrap();
        assert!(updated);
    }
}
