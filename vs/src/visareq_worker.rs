//! Visa request worker work on matching packets to policy in order to create visas.
//! The beating heart of the visa service.
//!
//! Each worker gets a single visa request and tried to run it throught the policy.
//! There are several outcomes:
//! - One or both actors may be missing (disconnected)
//! - One or both actors may need to be refreshed from attribute services.
//! - One or both actors may have expired authentication.
//! - A visa may already exist and policy has not changed, in which case we can use existing visa.
//! - The visa may be denied by policy.
//! - If at the end of all this a visa is permitted, then
//! - If poicy has not been updated in the meawhile, we issue a visa, else we fail it and hope caller tries again.
//!
//! Once a visa is issued we need to pick the path and figure out which nodes need to be informed.
//! There may be path constraints that make the visa invalid.
//!
//! Once we have a path, the visa is queued up for install on all the nodes and
//! returned to the caller.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::VSError;

pub struct PacketDesc {
    pub source: IpAddr,
    pub dest: IpAddr,
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
    pub comm_type: CommType,
}

pub enum CommType {
    bidirectional,
    unidirectional,
    rerequest,
}

pub struct Visa {}

async fn process_visa_request() -> Result<Visa, VSError> {
    todo!()
}

// TODO: Need to use try-from instead of from since there are so many possible errors!!

impl From<vsapi::vs_capnp::packet_desc::Reader<'_>> for PacketDesc {
    fn from(reader: vsapi::vs_capnp::packet_desc::Reader<'_>) -> Self {
        let src_ip = reader.get_source_addr().unwrap();
        let source = match src_ip.which().unwrap() {
            vsapi::vs_capnp::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4.unwrap().try_into().unwrap();
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            vsapi::vs_capnp::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6.unwrap().try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let dest_ip = reader.get_dest_addr().unwrap();
        let dest = match dest_ip.which().unwrap() {
            vsapi::vs_capnp::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4.unwrap().try_into().unwrap();
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            vsapi::vs_capnp::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6.unwrap().try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let source_port = reader.get_source_port();
        let dest_port = reader.get_dest_port();
        let protocol = reader.get_protocol();
        let comm_type = match reader.get_comm_type().unwrap() {
            vsapi::vs_capnp::CommType::Bidirectional => CommType::bidirectional,
            vsapi::vs_capnp::CommType::Unidirectional => CommType::unidirectional,
            vsapi::vs_capnp::CommType::Rerequest => CommType::rerequest,
        };

        PacketDesc {
            source,
            dest,
            source_port,
            dest_port,
            protocol,
            comm_type,
        }
    }
}
