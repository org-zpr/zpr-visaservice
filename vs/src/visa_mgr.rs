//! Manage the creating, storage and retrieval of visas for the visa service.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use crate::config;
use crate::error::VSError;
use libeval::eval::{Direction, Hit};

use zpr::vsapi_types::vsapi_ip_number as ip_proto;
use zpr::vsapi_types::{
    CommFlag, DockPep, EndpointT, IcmpPep, KeySet, PacketDesc, TcpUdpPep, Visa,
};

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
            (now + config::DEFAULT_EXPIRATION_SECONDS) * 1000
        };

        let (source_port, dest_port) = match pdesc.five_tuple.l4_protocol {
            ip_proto::TCP | ip_proto::UDP => {
                if pdesc.comm_flags == CommFlag::BiDirectional {
                    match hit.direction {
                        Direction::Forward => {
                            // client->server, allow any source port.
                            (0, pdesc.five_tuple.dst_port)
                        }
                        Direction::Reverse => {
                            // server->client, allow any dest port.
                            (pdesc.five_tuple.src_port, 0)
                        }
                    }
                } else {
                    // unidirectional, exact ports.
                    // TODO: What is ReRequest flag?
                    (pdesc.five_tuple.src_port, pdesc.five_tuple.dst_port)
                }
            }
            ip_proto::IPV6_ICMP => {
                // icmp type/code in ports
                (pdesc.five_tuple.src_port, pdesc.five_tuple.dst_port)
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

        let visa_id = self.take_next_visa_id();
        let visa = Visa {
            issuer_id: visa_id,
            config: 0,
            expires: UNIX_EPOCH + Duration::from_millis(expiration),
            src_addr: pdesc.five_tuple.src_address.clone(),
            dst_addr: pdesc.five_tuple.dst_address.clone(),
            dock_pep: pep,
            cons: None,
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
