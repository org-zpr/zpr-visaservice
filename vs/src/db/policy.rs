//! ValKey operations related to policy.
//!

use libeval::policy::Policy;
use openssl::hash::{Hasher, MessageDigest};
use redis::AsyncCommands;
use tracing::debug;

use crate::db;
use crate::db::Handle;
use crate::error::DBError;
use crate::logging::targets::REDIS;

const KEY_POLICIES: &str = "policies";
const KEY_POLICY: &str = "policy";

pub struct PolicyRepo {
    db: Handle,
}

impl PolicyRepo {
    pub fn new(db: &Handle) -> Self {
        PolicyRepo { db: db.clone() }
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
    ) -> Result<bool, DBError> {
        let mut vk_conn = self.db.conn.clone();
        let phash = hash_for_policy(policy)?;
        let maybe_curhash: Option<String> = vk_conn.hget("policy:current", "phash").await?;
        let curhash = match maybe_curhash {
            Some(h) => h,
            None => String::new(), // empty
        };
        let exists: bool =
            (curhash == phash) && vk_conn.exists(format!("{KEY_POLICIES}:{phash}")).await?;
        let mut updated = false;
        if !exists || force_overwrite {
            debug!(target: REDIS, "updating current policy in DB to phash {phash}");
            let pbuf = policy.get_serialized(); // get capn proto bytes

            let _: () = vk_conn
                .set(format!("{KEY_POLICIES}:{}", phash), pbuf.as_ref())
                .await?;

            let key_current = format!("{KEY_POLICY}:current");

            let _: () = vk_conn.hset(&key_current, "phash", phash).await?;

            let _: () = vk_conn
                .hset(&key_current, "ctime", db::gen_timestamp())
                .await?;
            updated = true;
        } else {
            debug!(target: REDIS, "set_current_policy found policy already set, hash={phash}");
        }

        Ok(updated)
    }
}

fn hash_for_policy(policy: &Policy) -> Result<String, DBError> {
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    if let Some(ctimestr) = policy.get_created() {
        hasher.update(ctimestr.as_bytes())?;
    } else {
        return Err(DBError::MissingRequired("created timestamp".to_string()));
    }
    if let Some(version) = policy.get_version() {
        hasher.update(&version.to_be_bytes())?;
    } else {
        return Err(DBError::MissingRequired("version".to_string()));
    }
    if let Some(md) = policy.get_metadata() {
        hasher.update(md.as_bytes())?;
    }
    let dig = hasher.finish()?;

    let phash = hex::encode(dig);
    Ok(phash)
}
