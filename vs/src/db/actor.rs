//! Redis/ValKey operations for actor state.
//!
//! Note that a ZADDR is a munged version of the ZPR address - colons replaced with dashes.
//! Note that the MUNGED_SERVICENAME is a db::KeyString - colons and '%' replaced with percent encoding.
//!
//! This updates:
//! - actor:<ZADDR> a hash for each connected actor
//! - actor:<ZADDR>:attrs a hash of attributes for each actor maps attribute keys to Attribug in JSON.
//! - service:<MUNGED_SERVICENAME> a hash. Includes key 'zaddr' with the ZADDR of the actor providing the service.
//! - nodes set of IP addresses  of all connected nodes.
//! - adapters set of IP addresses  of all connected adapters.

use libeval::actor::Actor;
use libeval::attribute::Attribute;
use redis::AsyncCommands;
use std::net::IpAddr;
use tracing::{debug, warn};

use crate::db::{Handle, KeyString, ZAddr, gen_timestamp};
use crate::error::DBError;
use crate::logging::targets::REDIS;

const KEY_ACTOR: &str = "actor";
const KEY_SERVICE: &str = "service";
const KEY_NODES: &str = "nodes";
const KEY_ADAPTERS: &str = "adapters";

pub struct ActorRepo {
    db: Handle,
}

impl ActorRepo {
    pub fn new(db_handle: &Handle) -> Self {
        ActorRepo {
            db: db_handle.clone(),
        }
    }

    /// Add an actor record.
    pub async fn add_actor(&self, actor: &Actor) -> Result<(), DBError> {
        let zpraddr = match actor.get_zpr_addr() {
            Some(addr) => addr.clone(),
            None => {
                return Err(DBError::MissingRequired(
                    "attempt to add actor with no ZPR address".into(),
                ));
            }
        };

        let base_key = actor_key_for(&zpraddr);

        let mut vk_conn = self.db.conn.clone();
        let exists: bool = vk_conn.exists(&base_key).await?;
        let ts = gen_timestamp();

        // Write the attributes. We write out the attributes in JSON.
        for (_idx, attr) in actor.attrs_iter().enumerate() {
            let _: () = vk_conn
                .hset(
                    attrs_key_for(&zpraddr),
                    attr.get_key(),
                    serde_json::to_string(&attr)?,
                )
                .await?;
        }

        // Get the identity keys as a vec, write as JSON array
        let identity_keys = actor
            .identity_keys_iter()
            .map(String::as_str)
            .collect::<Vec<_>>();

        let _: () = vk_conn
            .hset(
                &base_key,
                "identity_keys",
                serde_json::to_string(&identity_keys)?,
            )
            .await?;

        if !exists {
            // new, so write creation time
            let _: () = vk_conn.hset(&base_key, "ctime", &ts).await?;
        }
        // write update time
        let _: () = vk_conn.hset(&base_key, "utime", &ts).await?;

        // Redis keeps a service list of form service:<NAME>
        // Note that name is sanititized to replace colons with dashses, and dashes with double-dashes.
        //
        // This means that each service can have just one entry here which we may want
        // to reasses later -- for example a service may be provided by multiple actors.
        for service_name in actor.services_iter() {
            let svc_key_str = service_key_for(&service_name);
            let _: () = vk_conn
                .hset(&svc_key_str, "zpr_addr", &zpraddr.to_string())
                .await?;
        }

        if actor.is_node() {
            let _: () = vk_conn.sadd(KEY_NODES, zpraddr.to_string()).await?;
        } else {
            let _: () = vk_conn.sadd(KEY_ADAPTERS, zpraddr.to_string()).await?;
        }

        debug!(target: REDIS, "added actor to DB: addr={zpraddr} cn={:?} new={}", actor.get_cn(), !exists);
        Ok(())
    }

    /// Remove an actor record.
    pub async fn rm_actor_by_zpr_addr(&self, zpra: &std::net::IpAddr) -> Result<(), DBError> {
        let mut vk_conn = self.db.conn.clone();
        let base_key = actor_key_for(&zpra);

        // In order to remove the services, we need to reconsititute the actor to get the service list.
        if let Some(found_actor) = self.get_actor_by_zpr_addr(zpra).await.ok() {
            for service_name in found_actor.services_iter() {
                let _: () = vk_conn.del(&service_key_for(&service_name)).await?;
            }

            // If we got the actor, we can see if it is a node or not.
            if found_actor.is_node() {
                let _: () = vk_conn.srem(KEY_NODES, zpra.to_string()).await?;
            } else {
                let _: () = vk_conn.srem(KEY_ADAPTERS, zpra.to_string()).await?;
            }
        } else {
            warn!(target: REDIS, "attempt to remove actor not found in DB: addr={zpra}");
            // Not sure if this is a node or an adapter, so try both:
            let _: () = vk_conn.srem(KEY_NODES, zpra.to_string()).await?;
            let _: () = vk_conn.srem(KEY_ADAPTERS, zpra.to_string()).await?;
        }

        // remove actor:<ZADDR>:attrs entry
        let _: () = vk_conn.del(format!("{base_key}:attrs")).await?;

        // remove actor:<ZADDR> entry
        let _: () = vk_conn.del(&base_key).await?;

        debug!(target: REDIS, "removed actor from DB: addr={zpra}");
        Ok(())
    }

    /// Look up actor by ZPR address. Creates a new actor instance from the DB data if found.
    ///
    /// ## Errors
    /// - Returns `DBError::NotFound` if no actor found for the given ZPR address.
    pub async fn get_actor_by_zpr_addr(&self, zpra: &std::net::IpAddr) -> Result<Actor, DBError> {
        let mut vk_conn = self.db.conn.clone();
        let base_key = actor_key_for(&zpra);
        let exists: bool = vk_conn.exists(&base_key).await?;
        if !exists {
            return Err(DBError::NotFound(format!("actor not found: {}", zpra)));
        }

        let mut actor = Actor::new();

        // Load attributes from json.  The attributes are in 'actor:<ZADDR>:attrs' hash
        // each key is an attribute name, and the value is the JSON representation of the attribute.
        let attrs_map: std::collections::HashMap<String, String> =
            vk_conn.hgetall(format!("{base_key}:attrs")).await?;
        for (_key, attr_json) in attrs_map.iter() {
            let attr: Attribute = serde_json::from_str(attr_json)?;
            actor.add_attribute(attr)?;
        }

        // Then get the identity attribute key values.
        let identity_keys_json: String = vk_conn.hget(&base_key, "identity_keys").await?;
        let identity_keys: Vec<String> = serde_json::from_str(&identity_keys_json)?;
        for idkey in identity_keys.iter() {
            actor.add_identity_key(usize::MAX, idkey)?; // 0 means no expiration
        }
        Ok(actor)
    }
}

fn actor_key_for(zpr_addr: &IpAddr) -> String {
    let zaddr: ZAddr = zpr_addr.into();
    format!("{KEY_ACTOR}:{zaddr}")
}
fn attrs_key_for(zpr_addr: &IpAddr) -> String {
    let zaddr: ZAddr = zpr_addr.into();
    format!("{KEY_ACTOR}:{zaddr}:attrs")
}
fn service_key_for(service_name: &str) -> String {
    let svc_name_clean = KeyString::from(service_name);
    format!("{KEY_SERVICE}:{}", svc_name_clean.as_str())
}
