//! Manage the creating, storage and retrieval of visas for the visa service.

use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use crate::config;
use crate::db;
use crate::error::VSError;
use crate::logging::targets::VMGR;

use libeval::eval::{Direction, Hit};
use zpr::vsapi_types::vsapi_ip_number as ip_proto;
use zpr::vsapi_types::{
    CommFlag, DockPep, EndpointT, IcmpPep, KeySet, PacketDesc, TcpUdpPep, Visa,
};

use tracing::info;

pub struct VisaMgr {
    repo: db::VisaRepo,
}

impl VisaMgr {
    pub fn new(db: db::VisaRepo) -> Self {
        VisaMgr { repo: db }
    }

    // Placeholder implementation, called concurrently.
    // Using a const expiration (4 hrs).
    // No checking to see if visa already exists.
    // No storing of the visas.
    // Fake keys.
    pub async fn create_visa(
        &self,
        requesting_node: &IpAddr,
        pdesc: &PacketDesc,
        hit: &Hit,
    ) -> Result<Visa, VSError> {
        // Expiration is millis since UNIX EPOCH
        let expiration = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| VSError::InternalError("system time before UNIX EPOCH".to_string()))?
                .as_secs();
            (now + config::DEFAULT_EXPIRATION_SECONDS) * 1000
        };

        let (source_port, dest_port) = match pdesc.five_tuple.l4_protocol {
            ip_proto::TCP | ip_proto::UDP => {
                if pdesc.comm_flags == CommFlag::BiDirectional {
                    match hit.direction {
                        Direction::Forward => {
                            // client->server, allow any source port.
                            (0, pdesc.five_tuple.dest_port)
                        }
                        Direction::Reverse => {
                            // server->client, allow any dest port.
                            (pdesc.five_tuple.source_port, 0)
                        }
                    }
                } else {
                    // unidirectional, exact ports.
                    // TODO: What is ReRequest flag?
                    (pdesc.five_tuple.source_port, pdesc.five_tuple.dest_port)
                }
            }
            ip_proto::IPV6_ICMP => {
                // icmp type/code in ports
                (pdesc.five_tuple.source_port, pdesc.five_tuple.dest_port)
            }
            _ => {
                return Err(VSError::InternalError(format!(
                    "unsupported protocol for visa: {}",
                    pdesc.five_tuple.l4_protocol
                )));
            }
        };

        let pep = match pdesc.five_tuple.l4_protocol {
            ip_proto::TCP => DockPep::TCP(TcpUdpPep::new(
                source_port,
                dest_port,
                ep_from_dir(&hit.direction),
            )),
            ip_proto::UDP => DockPep::UDP(TcpUdpPep::new(
                source_port,
                dest_port,
                ep_from_dir(&hit.direction),
            )),
            ip_proto::IPV6_ICMP => DockPep::ICMP(IcmpPep::new(source_port as u8, dest_port as u8)),

            _ => unreachable!(), // already handled above
        };

        let visa_id = self.repo.get_next_visa_id().await?;
        let visa = Visa {
            issuer_id: visa_id,
            config: 0,
            expires: UNIX_EPOCH + Duration::from_millis(expiration),
            source_addr: pdesc.five_tuple.source_addr.clone(),
            dest_addr: pdesc.five_tuple.dest_addr.clone(),
            dock_pep: pep,
            cons: None,
            session_key: KeySet::new("secret".as_bytes(), "secret".as_bytes()),
        };

        self.repo.store_visa(requesting_node, &visa).await?;

        info!("created visa {visa_id}");
        Ok(visa)
    }

    /// Register that visa `visa_id` has been installed on node at ZPR address `node_addr`.
    pub async fn visa_installed(&self, visa_id: u64, node_addr: &IpAddr) -> Result<(), VSError> {
        self.repo
            .update_node_visa_state(node_addr, visa_id, db::NodeVisaState::Installed)
            .await?;
        Ok(())
    }

    /// Designed to be used to setup database in clean state as we prepare for a
    /// fresh node joining.
    pub async fn clear_node_state(&self, node_addr: &IpAddr) -> Result<(), VSError> {
        self.repo.clear_node_state(node_addr).await?;
        Ok(())
    }

    /// Remove all visas tied to the given node -- assumes that `node_addr` has departed.
    ///
    /// TODO: This probably needs a lock on the node address -- like we do not
    /// want the same node to be reconnecting while we are doing this clean up.
    ///
    /// TODO: Sometimes we want to keep track of visas installed on nodes so that
    /// nodes could restart and we can then just push them state.  TBD.
    ///
    /// For each visa that is marked installed or pending-install on the node,
    /// collect the ID.  Then wipe all the nodevisa records for the node.
    ///
    /// Now we have a bunch of visa IDs. For each ID, if the visa is installed
    /// or pending on some other node, update the state on that node to pending-revoke
    /// and then remove the visa:ID record.
    ///
    /// The housekeeping job will take care of updating the TODO lists and sending
    /// the revocation messages out to the other nodes.
    ///
    pub async fn remove_visas_for_node(&self, node_addr: &IpAddr) -> Result<(), VSError> {
        info!(target: VMGR, "TODO: remove visas for node {node_addr}");
        Ok(())
    }

    /// Remove all visas tied to the listed actors, assumes the actors have departed.
    pub async fn remove_visas_for_actors(&self, _actor_addrs: &[IpAddr]) -> Result<(), VSError> {
        info!(target: VMGR, "TODO: remove visas for actors now removed");
        Ok(())
    }
}

fn ep_from_dir(dir: &Direction) -> EndpointT {
    match dir {
        // Matched forward direction: client to server.
        Direction::Forward => EndpointT::Client,

        // Matched reverse direction: server to client.
        Direction::Reverse => EndpointT::Server,
    }
}
