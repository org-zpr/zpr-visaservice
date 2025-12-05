//! ValKey operations related to policy.
//!

use libeval::policy::Policy;
use openssl::hash::{Hasher, MessageDigest};
use redis::AsyncCommands;
use tracing::debug;

use crate::db;
use crate::error::DBError;
use crate::logging::targets::PDB;

/// Set the current policy information into the database.
/// Only updates the database if the current policy is different (by its phash) from the one already stored.
///
/// Return FALSE if nothing changed in the DB (ie, policy:current was already set)
pub async fn set_current_policy(mut vk_conn: db::Conn, policy: &Policy) -> Result<bool, DBError> {
    let phash = hash_for_policy(policy)?;
    let maybe_curhash: Option<String> = vk_conn.hget("policy:current", "phash").await?;
    let curhash = match maybe_curhash {
        Some(h) => h,
        None => String::new(), // empty
    };
    let exists = curhash == phash;
    if !exists {
        debug!(target: PDB, "updating current policy in DB to phash {phash}");
        let pbuf = policy.get_serialized(); // get capn proto bytes

        let _: () = vk_conn
            .set(format!("policy:{}", phash), pbuf.as_ref())
            .await?;

        let _: () = vk_conn.hset("policy:current", "phash", phash).await?;

        let _: () = vk_conn
            .hset("policy:current", "ctime", db::gen_timestamp())
            .await?;
    } else {
        debug!(target: PDB, "set_current_policy found policy already set, hash={phash}");
    }

    Ok(!exists)
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
