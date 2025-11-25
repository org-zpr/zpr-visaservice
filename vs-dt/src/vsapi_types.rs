//! API types that are converted into/out-of Capn Proto.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zpr::vsapi::v1 as vsapi;

use crate::error::DTError;
use crate::packet::ip_proto;
pub struct Visa {
    pub issuer_id: u64,
    pub expiration: u64, // VS uses milliseconds since epoch
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub dock_pep: DockPEP,
    pub constraints: Option<Vec<Constraint>>,
    pub session_key: KeySet,
}

pub enum DockPEP {
    Tcp(u16, u16, EndpointT), // (source port, dest port)
    Udp(u16, u16, EndpointT), // (source port, dest port)
    Icmp(u8, u8),             // (icmp type, icmp code)
}

pub enum EndpointT {
    Any,
    Server,
    Client,
}

pub enum Constraint {}

#[allow(dead_code)]
pub struct KeySet {
    ingress: Vec<u8>,
    egress: Vec<u8>,
}

pub enum VisaDenialReason {
    NoReasonGiven,
    NoMatch,
    Denied,
    SourceNotFound,
    DestNotFound,
    SourceAuthError,
    DestAuthError,
    QuotaExceeded,
}

/// A description of a packet between a sender and reciever.
#[allow(dead_code)]
pub struct PacketDesc {
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub protocol: u8,
    /// Source port or ICMP type
    pub source_port: u16,
    /// Destination port or ICMP code
    pub dest_port: u16,
    /// TODO: Can multiple flags be passed with the PacketDesc?
    pub comm_flags: CommFlag,
}

/// Special hint that is passed with a [PacketDesc].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommFlag {
    /// TODO: document this
    BiDirectional,
    /// TODO: document this
    UniDirectional,
    /// Is-a re-request, includes previous visa id.
    /// TODO: Hmm... Does this assumes a lot of state accessible to the evaluator?
    ReRequest(u64),
}

fn write_ip_addr(bldr: &mut vsapi::ip_addr::Builder<'_>, ip: &IpAddr) {
    match ip {
        IpAddr::V4(ipv4) => {
            let v4_buf = bldr.reborrow().init_v4(4);
            v4_buf.copy_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            let v6_buf = bldr.reborrow().init_v6(16);
            v6_buf.copy_from_slice(&ipv6.octets());
        }
    }
}

impl KeySet {
    pub fn new(ingress: &[u8], egress: &[u8]) -> Self {
        KeySet {
            ingress: ingress.to_vec(),
            egress: egress.to_vec(),
        }
    }
}

impl Visa {
    pub fn write_to(&self, bldr: &mut vsapi::visa::Builder<'_>) {
        bldr.set_issuer_id(self.issuer_id);
        bldr.set_expiration(self.expiration);
        let mut ip_bldr = bldr.reborrow().init_dest_addr();
        write_ip_addr(&mut ip_bldr, &self.dest_addr);
        let mut ip_bldr = bldr.reborrow().init_source_addr();
        write_ip_addr(&mut ip_bldr, &self.source_addr);
        match &self.dock_pep {
            DockPEP::Tcp(sport, dport, ept) => {
                let pep_bldr = bldr.reborrow().init_dock_pep();
                let mut tcp_bldr = pep_bldr.init_tcp();
                tcp_bldr.set_source_port(*sport);
                tcp_bldr.set_dest_port(*dport);
                match ept {
                    EndpointT::Any => tcp_bldr.set_enpoint(vsapi::EndpointT::Any),
                    EndpointT::Server => tcp_bldr.set_enpoint(vsapi::EndpointT::Server),
                    EndpointT::Client => tcp_bldr.set_enpoint(vsapi::EndpointT::Client),
                }
            }
            DockPEP::Udp(sport, dport, ept) => {
                let pep_bldr = bldr.reborrow().init_dock_pep();
                let mut udp_bldr = pep_bldr.init_udp();
                udp_bldr.set_source_port(*sport);
                udp_bldr.set_dest_port(*dport);
                match ept {
                    EndpointT::Any => udp_bldr.set_enpoint(vsapi::EndpointT::Any),
                    EndpointT::Server => udp_bldr.set_enpoint(vsapi::EndpointT::Server),
                    EndpointT::Client => udp_bldr.set_enpoint(vsapi::EndpointT::Client),
                }
            }
            DockPEP::Icmp(icmp_type, icmp_code) => {
                let pep_bldr = bldr.reborrow().init_dock_pep();
                let mut icmp_bldr = pep_bldr.init_icmp();
                let typecode: u16 = ((*icmp_type as u16) << 8) | (*icmp_code as u16);
                icmp_bldr.set_icmp_type_code(typecode);
            }
        }
        if self.constraints.is_some() {
            unimplemented!("visa constraints serialization not implemented yet");
        }
        let mut keyset_bldr = bldr.reborrow().init_session_key();
        keyset_bldr.set_format(vsapi::KeyFormat::ZprKF01);
        keyset_bldr.set_ingress_key(&self.session_key.ingress);
        keyset_bldr.set_egress_key(&self.session_key.egress);
    }
}

impl Into<vsapi::VisaDenyCode> for VisaDenialReason {
    fn into(self) -> vsapi::VisaDenyCode {
        match self {
            VisaDenialReason::NoReasonGiven => vsapi::VisaDenyCode::NoReason,
            VisaDenialReason::NoMatch => vsapi::VisaDenyCode::NoMatch,
            VisaDenialReason::Denied => vsapi::VisaDenyCode::Denied,
            VisaDenialReason::SourceNotFound => vsapi::VisaDenyCode::SourceNotFound,
            VisaDenialReason::DestNotFound => vsapi::VisaDenyCode::DestNotFound,
            VisaDenialReason::SourceAuthError => vsapi::VisaDenyCode::SourceAuthError,
            VisaDenialReason::DestAuthError => vsapi::VisaDenyCode::DestAuthError,
            VisaDenialReason::QuotaExceeded => vsapi::VisaDenyCode::QuotaExceeded,
        }
    }
}

impl TryFrom<vsapi::packet_desc::Reader<'_>> for PacketDesc {
    type Error = DTError;
    fn try_from(reader: vsapi::packet_desc::Reader<'_>) -> Result<Self, Self::Error> {
        let src_ip = reader.get_source_addr()?;
        let source = match src_ip.which().unwrap() {
            vsapi::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4?
                    .try_into()
                    .map_err(|_| DTError::InvalidArgument("invalid src_ip".into()))?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            vsapi::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6?
                    .try_into()
                    .map_err(|_| DTError::InvalidArgument("invalid src_ip".into()))?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let dest_ip = reader.get_dest_addr()?;
        let dest = match dest_ip.which().unwrap() {
            vsapi::ip_addr::V4(ipv4) => {
                let octets: [u8; 4] = ipv4?
                    .try_into()
                    .map_err(|_| DTError::InvalidArgument("invalid dest_ip".into()))?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            vsapi::ip_addr::V6(ipv6) => {
                let octets: [u8; 16] = ipv6?
                    .try_into()
                    .map_err(|_| DTError::InvalidArgument("invalid dest_ip".into()))?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };
        let source_port = reader.get_source_port();
        let dest_port = reader.get_dest_port();
        let protocol = reader.get_protocol();
        let comm_flags = match reader.get_comm_type().unwrap() {
            vsapi::CommType::Bidirectional => CommFlag::BiDirectional,
            vsapi::CommType::Unidirectional => CommFlag::UniDirectional,
            vsapi::CommType::Rerequest => CommFlag::ReRequest(0), // TODO
        };

        Ok(PacketDesc {
            source_addr: source,
            dest_addr: dest,
            source_port,
            dest_port,
            protocol,
            comm_flags,
        })
    }
}

impl PacketDesc {
    pub fn new_tcp(source_addr: &str, dest_addr: &str, source_port: u16, dest_port: u16) -> Self {
        PacketDesc {
            source_addr: source_addr.parse().unwrap(),
            dest_addr: dest_addr.parse().unwrap(),
            protocol: ip_proto::TCP,
            source_port,
            dest_port,
            comm_flags: CommFlag::BiDirectional,
        }
    }

    pub fn new_udp(source_addr: &str, dest_addr: &str, source_port: u16, dest_port: u16) -> Self {
        PacketDesc {
            source_addr: source_addr.parse().unwrap(),
            dest_addr: dest_addr.parse().unwrap(),
            protocol: ip_proto::UDP,
            source_port,
            dest_port,
            comm_flags: CommFlag::BiDirectional,
        }
    }

    pub fn new_icmpv6(source_addr: &str, dest_addr: &str, icmp_type: u8, icmp_code: u8) -> Self {
        PacketDesc {
            source_addr: source_addr.parse().unwrap(),
            dest_addr: dest_addr.parse().unwrap(),
            protocol: ip_proto::IPV6_ICMP,
            source_port: icmp_type as u16,
            dest_port: icmp_code as u16,
            comm_flags: CommFlag::UniDirectional,
        }
    }

    pub fn is_tcpudp(&self) -> bool {
        self.protocol == ip_proto::TCP || self.protocol == ip_proto::UDP
    }
}
