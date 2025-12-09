//! Redis/ValKey operations related to nodes (as distinct from actors).
//!
//!
//! This updates:
//! - node:<ZADDR> metadata about a node connection.
//! - node:<ZADDR>:XXX  TODO - other details about node housekeeping.

use libeval::actor::Actor;
use libeval::attribute::key;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;
use tracing::debug;

use crate::db::{Handle, ZAddr};
use crate::error::DBError;
use crate::logging::targets::REDIS;

// We keep this whole thing as JSON in node:<ZADDR>
#[derive(Debug, Serialize, Deserialize)]
pub struct Node {
    pub ctime: SystemTime,
    pub zpr_addr: IpAddr,
    pub cn: String,
    pub substrate_addr: SocketAddr,
}

pub struct NodeRepo {
    db: Handle,
}

impl Node {
    /// Create a Node object from a node Actor. Returns errors if the actor
    /// is not setup correctly to be a node.
    pub fn new_from_node_actor(actor: &Actor) -> Result<Self, DBError> {
        if !actor.is_node() {
            return Err(DBError::InvalidData(
                "attempt to create Node from non-node actor".into(),
            ));
        }
        let cn = match actor.get_cn() {
            Some(c) => c.to_string(),
            None => {
                return Err(DBError::MissingRequired("node actor missing CN".into()));
            }
        };
        let zpr_addr = match actor.get_zpr_addr() {
            Some(addr) => addr.clone(),
            None => {
                return Err(DBError::MissingRequired(
                    "node actor missing ZPR address".into(),
                ));
            }
        };
        let substrate_addr = match actor.get_attribute(key::SUBSTRATE_ADDR) {
            Some(addr) => addr.get_value().parse::<SocketAddr>().map_err(|e| {
                DBError::InvalidData(format!(
                    "failed to parse substrate address attribute as SocketAddr: {}",
                    e
                ))
            })?,
            None => {
                return Err(DBError::MissingRequired(
                    "node actor missing substrate address".into(),
                ));
            }
        };
        Ok(Node {
            ctime: SystemTime::now(),
            zpr_addr,
            cn,
            substrate_addr,
        })
    }
}

impl NodeRepo {
    pub fn new(db: &Handle) -> Self {
        NodeRepo { db: db.clone() }
    }

    /// Add the node state record.
    pub async fn add_node(&self, node: &Node) -> Result<(), DBError> {
        let mut vk_conn = self.db.conn.clone();
        let _: () = vk_conn
            .set(
                &node_key_for_node(&node.zpr_addr),
                serde_json::to_string(&node)?,
            )
            .await?;
        Ok(())
    }

    /// Add state that an adapter is connected to a node.
    pub async fn add_connected_adater(
        &self,
        node_addr: &IpAddr,
        adapter_addr: &IpAddr,
    ) -> Result<(), DBError> {
        let mut vk_conn = self.db.conn.clone();
        let _: () = vk_conn
            .sadd(
                connections_key_for_node(node_addr),
                adapter_addr.to_string(),
            )
            .await?;
        Ok(())
    }

    /// Get the list of adapter addresses connected to the given node.
    pub async fn get_connected_adapters(&self, node_addr: &IpAddr) -> Result<Vec<IpAddr>, DBError> {
        let mut vk_conn = self.db.conn.clone();
        let adapter_zaddr_strings: Vec<String> = vk_conn
            .smembers(connections_key_for_node(node_addr))
            .await?;
        // convert to IpAddr - bad parse causes error
        let mut adapter_addrs = Vec::new();
        for addr_str in adapter_zaddr_strings {
            match addr_str.parse::<IpAddr>() {
                Ok(addr) => adapter_addrs.push(addr),
                Err(e) => {
                    return Err(DBError::InvalidData(format!(
                        "failed to parse address string '{}' as IpAddr: {}",
                        addr_str, e
                    )));
                }
            }
        }
        Ok(adapter_addrs)
    }

    /// Removes all the ancillary node tables.
    /// Caller must make sure that any cascading state is also removed.
    pub async fn remove_node(&self, node_addr: &IpAddr) -> Result<(), DBError> {
        let mut vk_conn = self.db.conn.clone();
        let _: () = vk_conn.del(&connections_key_for_node(node_addr)).await?;
        let _: () = vk_conn.del(&todo_vinstall_key_for_node(node_addr)).await?;
        let _: () = vk_conn.del(&todo_vrevoke_key_for_node(node_addr)).await?;
        let _: () = vk_conn.del(&todo_crevoke_key_for_node(node_addr)).await?;
        let _: () = vk_conn.del(&node_key_for_node(node_addr)).await?;
        debug!(target: REDIS, "removed node state for node at addr {}", node_addr);
        Ok(())
    }
}

fn node_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}")
}

fn connections_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:connections")
}

fn todo_vinstall_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:todo:vinstall")
}

fn todo_vrevoke_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:todo:vrevoke")
}

fn todo_crevoke_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:todo:crevoke")
}
