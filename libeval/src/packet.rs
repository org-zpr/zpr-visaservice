use std::net;

pub mod ip_proto {
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6_ICMP: u8 = 58;
}

pub mod tcp {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// A description of a packet between a sender and reciever.
#[allow(dead_code)]
pub struct PacketDesc {
    pub source_addr: net::IpAddr,
    pub dest_addr: net::IpAddr,
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

impl PacketDesc {
    pub fn new_tcp_req(
        source_addr: &str,
        dest_addr: &str,
        source_port: u16,
        dest_port: u16,
    ) -> Self {
        PacketDesc {
            source_addr: source_addr.parse().unwrap(),
            dest_addr: dest_addr.parse().unwrap(),
            protocol: ip_proto::TCP,
            source_port,
            dest_port,
            comm_flags: CommFlag::BiDirectional,
        }
    }

    pub fn new_udp_req(
        source_addr: &str,
        dest_addr: &str,
        source_port: u16,
        dest_port: u16,
    ) -> Self {
        PacketDesc {
            source_addr: source_addr.parse().unwrap(),
            dest_addr: dest_addr.parse().unwrap(),
            protocol: ip_proto::UDP,
            source_port,
            dest_port,
            comm_flags: CommFlag::BiDirectional,
        }
    }

    pub fn new_icmpv6_req(
        source_addr: &str,
        dest_addr: &str,
        icmp_type: u8,
        icmp_code: u8,
    ) -> Self {
        PacketDesc {
            source_addr: source_addr.parse().unwrap(),
            dest_addr: dest_addr.parse().unwrap(),
            protocol: ip_proto::IPV6_ICMP,
            source_port: icmp_type as u16,
            dest_port: icmp_code as u16,
            comm_flags: CommFlag::UniDirectional,
        }
    }
}
