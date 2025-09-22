use std::net;

pub enum EvalDecision {
    /// Takes an explanator string.
    NoMatch(String),

    /// All mathcing allow permissions are returned.
    Allow(Vec<PermissionAllow>),

    /// All matching deny permissions are returned.
    Deny(Vec<PermissionDeny>),
}

#[allow(dead_code)]
pub struct PermissionAllow {
    /// Actual ZPL from policy.
    zpl: String,

    /// Keys that matched from the source actor.
    matching_source_keys: Vec<String>,

    /// Keys that matched from the dest actor.
    matching_dest_keys: Vec<String>,

    /// Computed expiration for this permission (if any) in unix time millisonds.
    expiration_ms: u64,
    source_addr: net::IpAddr,
    dest_addr: net::IpAddr,
    protocol: u8,
    source_port: u16,
    dest_port: u16,
    comm_opts: Option<Vec<CommOpt>>,

    /// If there is a signal attached to this permission it is returned here.
    signal: Option<Signal>,
}

pub enum CommOpt {
    ReversePinhole,
    // others TBD
}

#[allow(dead_code)]
pub struct PermissionDeny {
    /// Actual ZPL from policy.
    zpl: String,
    /// Keys that matched from the source actor.
    matching_source_keys: Vec<String>,

    /// Keys that matched from the dest actor.
    matching_dest_keys: Vec<String>,

    /// If there is a signal attached to this permission it is returned here.
    signal: Option<Signal>,
}

#[allow(dead_code)]
pub struct Signal {
    message: String,
    service: String,
}
