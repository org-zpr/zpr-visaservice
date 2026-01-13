//! Redis/ValKey operations related to visas.
//!
//! This updates:
//! - visa:next_visa_id a counter for the next visa ID to use (actually this is set to the last visa ID handed out).
//! - visa:<ID> a hash of metadata about each visa.
//! - visas:<ID>:blob the capnp encoded visa blob itself.
//! - nodevisa:<ZADDR>:<ID> a hash of state about each visa on each node.

use capnp;

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tracing::{debug, error, warn};

use ::zpr::vsapi::v1 as vsapi;
use zpr::vsapi_types::Visa;
use zpr::vsapi_types_writers::WriteTo;

use crate::db::{Handle, ZAddr, gen_timestamp};
use crate::error::DBError;
use crate::logging::targets::REDIS;

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
    db: Handle,
}

impl VisaRepo {
    pub fn new(db: &Handle) -> Self {
        // TODO: Could sanity check db state here.
        VisaRepo { db: db.clone() }
    }

    pub async fn get_next_visa_id(&self) -> Result<u64, DBError> {
        let mut conn = self.db.conn.clone();
        let next_id: u64 = conn.incr(KEY_NEXT_VISA_ID, 1).await?;
        Ok(next_id)
    }

    /// Remove references to a visa from the state datbase. Caller must make sure
    /// that any revocation messages or whatever have already been sent.
    async fn clean_up(&self, visa_id: u64) -> Result<(), DBError> {
        let mut vk_conn = self.db.conn.clone();

        let blob_key = blob_key_for_visa(visa_id);
        let visa_id_key = visa_key_for_visa(visa_id);

        let _: () = redis::pipe()
            .atomic()
            .del(&blob_key)
            .del(&visa_id_key)
            .query_async(&mut vk_conn)
            .await?;

        // Remove any nodevisa references to this visa.
        let nodevisa_keys = {
            let mut found_keys = Vec::new();
            let mut iter: redis::AsyncIter<String> = vk_conn
                .scan_match(format!("{KEY_NODEVISA}:*:{visa_id}"))
                .await?;
            while let Some(key_res) = iter.next_item().await {
                if let Ok(key) = key_res {
                    found_keys.push(key);
                }
            }
            found_keys
        };
        if !nodevisa_keys.is_empty() {
            let mut piper = redis::pipe();
            for k in &nodevisa_keys {
                debug!(target: REDIS, "removing nodevisa key {}", k);
                piper.del(k);
            }
            let _: () = piper.query_async(&mut vk_conn).await?;
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
        let mut vk_conn = self.db.conn.clone();
        let nodevisa_keys = {
            let mut found_keys = Vec::new();
            let mut iter: redis::AsyncIter<String> = vk_conn
                .scan_match(format!("{KEY_NODEVISA}:{zaddr}:*"))
                .await?;
            while let Some(key_res) = iter.next_item().await {
                if let Ok(key) = key_res {
                    found_keys.push(key);
                }
            }
            found_keys
        };
        if !nodevisa_keys.is_empty() {
            let mut piper = redis::pipe();
            for k in &nodevisa_keys {
                debug!(target: REDIS, "removing nodevisa key {}", k);
                piper.del(k);
            }
            let _: () = piper.query_async(&mut vk_conn).await?;
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
                warn!(target: REDIS, "failed to store visa: {}, attempting cleanup", visa.issuer_id);
                match self.clean_up(visa.issuer_id).await {
                    Ok(_) => (),
                    Err(cleanup_err) => {
                        error!(target: REDIS, "failed to store visa {} and clean up failed too: {}", visa.issuer_id, cleanup_err);
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

        let mut vk_conn = self.db.conn.clone();

        //
        // visa:<ID>:blob -> <capn proto bytes>
        //
        let _: () = vk_conn
            .set_ex(&blob_key_for_visa(visa_id), &words, expiration_seconds)
            .await?;

        let key_visa = visa_key_for_visa(visa_id);

        //
        // visa:<ID>
        //       |- requesting_node -> string, zpr address
        //       |- ctime           -> string, timestamp
        //
        let _: () = vk_conn
            .hset_multiple(
                &key_visa,
                &[
                    ("requesting_node", requesting_node.to_string().as_str()),
                    ("ctime", &gen_timestamp()),
                ],
            )
            .await?;
        let _: () = vk_conn.expire(&key_visa, expiration_seconds as i64).await?;

        //
        // nodevisa:<ZADDR>:<ID>
        //                   |- state -> string, JSON serialized NodeVisaState
        //                   |- utime -> string, timestamp
        //

        // TODO: We may want to use a struct here for the whole state entry and just serialize it all
        // as JSON, but for now am leaving open option of just updating fields individually using redis.
        let key_nodevisa = node_visa_key_for_visa(requesting_node, visa_id);
        let _: () = vk_conn
            .hset_multiple(
                &key_nodevisa,
                &[
                    ("state", serde_json::to_string(&nstate)?),
                    ("utime", gen_timestamp()),
                ],
            )
            .await?;
        let _: () = vk_conn
            .expire(&key_nodevisa, expiration_seconds as i64)
            .await?;

        debug!(target: REDIS, "stored visa {visa_id} expires in {expiration_seconds} seconds");
        Ok(())
    }

    /// Update the nodevisa state information for the node and visa.
    pub async fn update_node_visa_state(
        &self,
        node_addr: &IpAddr,
        visa_id: u64,
        new_state: NodeVisaState,
    ) -> Result<(), DBError> {
        let mut vk_conn = self.db.conn.clone();

        let key_nodevisa = node_visa_key_for_visa(node_addr, visa_id);
        if !vk_conn.exists(&key_nodevisa).await? {
            return Err(DBError::NotFound(format!(
                "node-visa record not found: {key_nodevisa}"
            )));
        }
        let _: () = vk_conn
            .hset_multiple(
                &key_nodevisa,
                &[
                    ("state", serde_json::to_string(&new_state)?),
                    ("last_update", gen_timestamp()),
                ],
            )
            .await?;

        debug!(target: REDIS, "updated nodevisa state node={node_addr} visa={visa_id} -> {new_state:?}");
        Ok(())
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
