use std::net::{IpAddr, SocketAddr};

use crate::error::VSError;

pub struct ConnectionControl {
    // Placeholder for connection control data and methods
}

pub struct NodeId {
    substrate_addr: SocketAddr,
    zpr_addr: IpAddr,
    cn: String,
}

impl ConnectionControl {
    // Must support calling from multiple threads
    pub fn authenticate_node(
        &self,
        _challenge_presented: Vec<u8>,
        _timestamp: u64,
        _cn: String,
        _challenge_response: Vec<u8>,
    ) -> Result<NodeId, VSError> {
        Err(VSError::AuthenticationFailed) // TODO
    }
}
