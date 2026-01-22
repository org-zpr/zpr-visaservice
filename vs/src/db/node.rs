//! Redis/ValKey operations related to nodes (as distinct from actors).
//!
//!
//! This updates:
//! - node:<ZADDR> a json Node struct -- metadata about a node connection.
//! - node:<ZADDR>:connections a set of adapter addresses connected to the node.
//!
//! Future stuff (not yet implemented):
//! - node:<ZADDR>:todo:vinstall - ordered list of visa IDs to be installed on the node
//! - node:<ZADDR>:todo:vrevoke - ordered list of visa IDs to be revoked from the node
//! - node:<ZADDR>:todo:crevoke - ordered list of authentication IDs (TBD??) to be revoked from the node

use libeval::actor::Actor;
use libeval::attribute::key;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::debug;

use crate::db::{DbConnection, DbOp, ZAddr};
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

// Wrap a SocketAddr for easy serialization.
#[derive(Debug, Serialize, Deserialize)]
struct SAWrapper {
    pub vss_addr: SocketAddr,
}

pub struct NodeRepo {
    db: Arc<dyn DbConnection>,
}

impl NodeRepo {
    pub fn new(db: Arc<dyn DbConnection>) -> Self {
        NodeRepo { db }
    }

    /// Add/overwrite the node state record. This assumes this is a new node being added.
    ///
    /// A node record is assoicated with an actor that is a node role.
    /// Nodes authenticate with the visa service directly.
    /// One node is also the visa service's dock.
    pub async fn add_node(&self, node: &Node) -> Result<(), DBError> {
        //
        // node:<ZADDR> -> string, json formatted Node struct.
        //
        self.db
            .set(
                &node_key_for_node(&node.zpr_addr),
                &serde_json::to_string(&node)?,
            )
            .await?;
        Ok(())
    }

    /// Keep track of the VSS address for the node.
    pub async fn set_node_vss(
        &self,
        node_zpr_addr: &IpAddr,
        vss_addr: &SocketAddr,
    ) -> Result<(), DBError> {
        let does_exist: bool = self.db.exists(&node_key_for_node(node_zpr_addr)).await?;
        if !does_exist {
            return Err(DBError::NotFound(format!(
                "node not found for address {}",
                node_zpr_addr
            )));
        }
        self.db
            .set(
                &vss_key_for_node(node_zpr_addr),
                &serde_json::to_string(&SAWrapper {
                    vss_addr: *vss_addr,
                })?,
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
        //
        // node:<ZADDR>:connections -> SET [ <zpr_address as string> ]
        //
        self.db
            .sadd(
                &connections_key_for_node(node_addr),
                &adapter_addr.to_string(),
            )
            .await?;
        Ok(())
    }

    /// Get the list of adapter addresses connected to the given node.
    pub async fn get_connected_adapters(&self, node_addr: &IpAddr) -> Result<Vec<IpAddr>, DBError> {
        let adapter_zaddr_strings = self
            .db
            .smembers(&connections_key_for_node(node_addr))
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
    pub async fn remove_node(&self, node_addr: &IpAddr) -> Result<(), DBError> {
        let ops = vec![
            DbOp::Del(connections_key_for_node(node_addr)),
            DbOp::Del(todo_vinstall_key_for_node(node_addr)),
            DbOp::Del(todo_vrevoke_key_for_node(node_addr)),
            DbOp::Del(todo_crevoke_key_for_node(node_addr)),
            DbOp::Del(node_key_for_node(node_addr)),
            DbOp::Del(vss_key_for_node(node_addr)),
        ];
        self.db.atomic_pipeline(&ops).await?;
        debug!(target: REDIS, "removed node state for node at addr {}", node_addr);
        Ok(())
    }
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
            Some(addr) => addr
                .get_single_value()
                .map_err(|e| {
                    DBError::InvalidData(format!(
                        "failed to get single value for substrate address: {}",
                        e
                    ))
                })?
                .parse::<SocketAddr>()
                .map_err(|e| {
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

fn node_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}")
}

fn vss_key_for_node(addr: &IpAddr) -> String {
    let zaddr = ZAddr::from(addr);
    format!("node:{zaddr}:vss")
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
