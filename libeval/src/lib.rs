pub mod eval;
pub mod zpr_policy;

use core::net;

/// A description of a packet between a sender and reciever.
#[allow(dead_code)]
pub struct PacketDesc {
    source_addr: net::IpAddr,
    dest_addr: net::IpAddr,
    protocol: u8,
    /// Source port or ICMP type
    source_port: u16,
    /// Destination port or ICMP code
    dest_port: u16,
    /// TODO: Can multiple flags be passed with the PacketDesc?
    comm_flags: CommFlag,
}

/// Special hint that is passed with a [PacketDesc].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommFlag {
    /// TODO: document this
    BiDirectional,
    /// TODO: document this
    UniDirectional,
    /// TODO: document this
    ReRequest,
}

/// TODO
pub struct Actor {}
