//! Redis/ValKey operations for actor state.
//!
//! Note that a ZADDR is a munged version of the ZPR address - colons replaced with dashes.
//! Note that the MUNGED_SERVICENAME is a db::KeyString - colons and '%' replaced with percent encoding.
//!
//! This updates:
//! - actor:<ZADDR> a hash for each connected actor
//! - actor:<ZADDR>:attrs a hash of attributes for each actor maps attribute keys to Attribug in JSON.
//! - actor:<ZADDR>:services a set of service names offered by the actor.
//! - service:<MUNGED_SERVICENAME> a hash. Includes key 'zpr_addr' with the ZPR address (string) of the actor providing the service.
//! - nodes set of IP addresses  of all connected nodes.
//! - adapters set of IP addresses  of all connected adapters.

use libeval::actor::Actor;
use libeval::attribute::Attribute;
use redis::AsyncCommands;
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::{debug, error, warn};

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

    /// Undo all the redis additions performed by `add_actor`.
    async fn clean_up(&self, zpraddr: &IpAddr) -> Result<(), DBError> {
        let mut vk_conn = self.db.conn.clone();

        let zpraddr_str = zpraddr.to_string();

        let base_key = actor_key_for(&zpraddr);
        let attrs_key = attrs_key_for(&zpraddr);
        let services_key = actor_services_key_for(&zpraddr);

        // Sanity check- remove any existing records for this actor.
        // Including any stale service records.
        let _: () = redis::pipe()
            .atomic()
            .del(&base_key)
            .del(&attrs_key)
            .srem(KEY_NODES, &zpraddr_str)
            .srem(KEY_ADAPTERS, &zpraddr_str)
            .query_async(&mut vk_conn)
            .await?;

        if vk_conn.exists(&services_key).await? {
            let service_names: HashSet<String> = vk_conn.smembers(&services_key).await?;
            if !service_names.is_empty() {
                let mut piper = redis::pipe();
                for name in &service_names {
                    // The stale names may actually be valid names on new actors. So we need to check the
                    // zaddr value before deleting.
                    let svc_key = service_key_for(&name);
                    let actor_addr_str: Option<String> = vk_conn.hget(&svc_key, "zpr_addr").await?;
                    if let Some(actor_addr) = actor_addr_str {
                        if actor_addr != zpraddr_str {
                            continue;
                        }
                        piper.del(&service_key_for(&name));
                    }
                }
                let _: () = piper.query_async(&mut vk_conn).await?;
            }
            let _: () = vk_conn.del(&services_key).await?;
        }
        Ok(())
    }

    pub async fn add_actor(&self, actor: &Actor) -> Result<(), DBError> {
        match self.try_add_actor(actor).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Attempt to clean up after ourselves...
                warn!(target: REDIS, "add_actor failed, attempting cleanup");
                if let Some(zpraddr) = actor.get_zpr_addr() {
                    match self.clean_up(zpraddr).await {
                        Ok(_) => (),
                        Err(cleanup_err) => {
                            error!(target: REDIS, "actor insert failed and so did clean up for addr={}: {}", zpraddr, cleanup_err);
                        }
                    }
                }
                Err(e)
            }
        }
    }

    /// Add an actor record which must only be called after initial authentication (there
    /// will likely be changes to an actor later from trusted services or re-authentication,
    /// but the updates should use a different function.)
    async fn try_add_actor(&self, actor: &Actor) -> Result<(), DBError> {
        let zpraddr = match actor.get_zpr_addr() {
            Some(addr) => addr.clone(),
            None => {
                return Err(DBError::MissingRequired(
                    "attempt to add actor with no ZPR address".into(),
                ));
            }
        };

        self.clean_up(&zpraddr).await?;

        let mut vk_conn = self.db.conn.clone();

        let zpraddr_str = zpraddr.to_string();
        let base_key = actor_key_for(&zpraddr);
        let attrs_key = attrs_key_for(&zpraddr);
        let services_key = actor_services_key_for(&zpraddr);

        let ts = gen_timestamp();

        //
        // actor:<ZADDR>:attrs
        //                |- <key> -> JSON(<Attribute>)
        //
        // Write the attributes. We write out the attributes in JSON.
        for attr in actor.attrs_iter() {
            let _: () = vk_conn
                .hset(&attrs_key, attr.get_key(), serde_json::to_string(&attr)?)
                .await?;
        }

        //
        // actor:<ZADDR>
        //         |- identity_keys -> JSON(<IdentityKeysVec>)
        //         |- ctime -> string
        //         |- utime -> string
        //

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
        let _: () = vk_conn.hset_nx(&base_key, "ctime", &ts).await?; // set create time only if not already there.
        let _: () = vk_conn.hset(&base_key, "utime", &ts).await?; // always set update time

        //
        // service:<NAME>
        //           |- zpr_addr -> string
        //
        // actor:<ZADDR>:services -> SET[ <service_name> ]
        //

        // This means that each service can have just one entry here which we may want
        // to reasses later -- for example a service may be provided by multiple actors.
        for service_name in actor.services_iter() {
            debug!(target: REDIS, "adding service for actor: addr={zpraddr} service={service_name}");
            let svc_key_str = service_key_for(&service_name);
            let _: () = vk_conn
                .hset(&svc_key_str, "zpr_addr", &zpraddr.to_string())
                .await?;
            let _: () = vk_conn.sadd(&services_key, &service_name).await?;
        }

        //
        // One of:
        //    nodes    -> SET [ <zpr_address_string> ]
        //    adapters -> SET [ <zpr_address_string> ]
        //
        if actor.is_node() {
            let _: () = vk_conn.sadd(KEY_NODES, &zpraddr_str).await?;
        } else {
            let _: () = vk_conn.sadd(KEY_ADAPTERS, &zpraddr_str).await?;
        }

        debug!(target: REDIS, "added actor to DB: addr={zpraddr} cn={:?} node?={}", actor.get_cn(), actor.is_node());
        Ok(())
    }

    /// Remove actor from the state database, including all services.
    pub async fn rm_actor_by_zpr_addr(&self, zpra: &std::net::IpAddr) -> Result<(), DBError> {
        self.clean_up(zpra).await?;
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

fn actor_services_key_for(zpr_addr: &IpAddr) -> String {
    let zaddr: ZAddr = zpr_addr.into();
    format!("{KEY_ACTOR}:{zaddr}:services")
}
