use serde::Serialize;
use std::fmt;
use std::net;

/// VisaProps is most of the information needed to create a visa.
/// Does not set an expiration unless one is part of a policy constraint.
#[derive(Serialize, Debug)]
#[allow(dead_code)]
pub struct VisaProps {
    pub source_addr: net::IpAddr,
    pub dest_addr: net::IpAddr,
    pub protocol: u8,
    pub source_port: u16,
    pub dest_port: u16,
    pub constraints: Option<Vec<Constraint>>,
    pub comm_opts: Option<Vec<CommOpt>>,
    pub zpl: String,
}

/// Just a bunch of accessors to help keep API clean.
impl VisaProps {
    pub fn get_source_addr(&self) -> net::IpAddr {
        self.source_addr
    }
    pub fn get_dest_addr(&self) -> net::IpAddr {
        self.dest_addr
    }
    pub fn get_protocol(&self) -> u8 {
        self.protocol
    }
    pub fn get_source_port(&self) -> u16 {
        self.source_port
    }
    pub fn get_dest_port(&self) -> u16 {
        self.dest_port
    }
    pub fn get_constraints(&self) -> Option<&[Constraint]> {
        self.constraints.as_deref()
    }
    pub fn get_comm_opts(&self) -> Option<&[CommOpt]> {
        self.comm_opts.as_deref()
    }
    pub fn get_zpl(&self) -> &str {
        &self.zpl
    }
}

/// Canonical "short-form" visa stringer.
impl fmt::Display for VisaProps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}]:{} -> [{}]:{} proto {} [opts:{:?}]",
            self.source_addr,
            self.source_port,
            self.dest_addr,
            self.dest_port,
            self.protocol,
            self.comm_opts
        )
    }
}

/// Policy may include constraints on the permission.
#[derive(Debug, Serialize)]
pub enum Constraint {
    /// unix time seconds for expiration of permission.
    ExpiresAtUnixSeconds(u64),
}

/// Policy may dictate certain communication pattern options.
#[derive(Debug, Serialize)]
pub enum CommOpt {
    // TODO: How to use this?
    ReversePinhole,
    // others TBD?
}
