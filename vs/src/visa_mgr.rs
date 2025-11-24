//! Manage the creating, storage and retrieval of visas for the visa service.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::VSError;
use crate::zpr;
use libeval::eval::{Direction, Hit};
use vs_dt::packet::ip_proto;
use vs_dt::vsapi_types::{CommFlag, DockPEP, EndpointT, KeySet, PacketDesc, Visa};

use tracing::info;

pub struct VisaMgr {
    next_visa_id: AtomicU64,
}

impl VisaMgr {
    pub fn new() -> Self {
        VisaMgr {
            next_visa_id: AtomicU64::new(1),
        }
    }

    fn take_next_visa_id(&self) -> u64 {
        self.next_visa_id.fetch_add(1, Ordering::Relaxed)
    }

    // Placeholder implementation, called concurrently.
    // Using a const expiration (4 hrs).
    // No checking to see if visa already exists.
    // No storing of the visas.
    // Fake keys.
    pub fn create_visa(&self, pdesc: &PacketDesc, hit: &Hit) -> Result<Visa, VSError> {
        // Expiration is millis since UNIX EPOCH
        let expiration = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| VSError::InternalError("system time before UNIX EPOCH".to_string()))?
                .as_secs();
            (now + zpr::DEFAULT_EXPIRATION_SECONDS) * 1000
        };

        let (source_port, dest_port) = match pdesc.protocol {
            ip_proto::TCP | ip_proto::UDP => {
                if pdesc.comm_flags == CommFlag::BiDirectional {
                    match hit.direction {
                        Direction::Forward => {
                            // client->server, allow any source port.
                            (0, pdesc.dest_port)
                        }
                        Direction::Reverse => {
                            // server->client, allow any dest port.
                            (pdesc.source_port, 0)
                        }
                    }
                } else {
                    // unidirectional, exact ports.
                    // TODO: What is ReRequest flag?
                    (pdesc.source_port, pdesc.dest_port)
                }
            }
            ip_proto::IPV6_ICMP => {
                // icmp type/code in ports
                (pdesc.source_port, pdesc.dest_port)
            }
            _ => {
                return Err(VSError::InternalError(format!(
                    "unsupported protocol for visa: {}",
                    pdesc.protocol
                )));
            }
        };

        let pep = match pdesc.protocol {
            ip_proto::TCP => DockPEP::Tcp(source_port, dest_port, ep_from_dir(&hit.direction)),
            ip_proto::UDP => DockPEP::Udp(source_port, dest_port, ep_from_dir(&hit.direction)),
            ip_proto::IPV6_ICMP => DockPEP::Icmp(source_port as u8, dest_port as u8),

            _ => unreachable!(), // already handled above
        };

        let visa_id = self.take_next_visa_id();
        let visa = Visa {
            issuer_id: visa_id,
            expiration,
            source_addr: pdesc.source_addr.clone(),
            dest_addr: pdesc.dest_addr.clone(),
            dock_pep: pep,
            constraints: None,
            session_key: KeySet::new("secret".as_bytes(), "secret".as_bytes()),
        };
        info!("created visa {visa_id}");
        Ok(visa)
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
