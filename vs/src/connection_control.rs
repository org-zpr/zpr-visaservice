use std::net::{IpAddr, SocketAddr};
use tracing::info;

use vsapi::vs_capnp as vsapi;

use crate::error::VSError;
use crate::logging::targets::CC;

pub struct ConnectionControl {
    // Placeholder for connection control data and methods
}

// Placeholder.
// Authentication will end up creating the node "actor" struct so probably
// that will be returned not this Node-Id thing.  And remember that the node
// authentication will have an expiration.
pub struct NodeId {
    substrate_addr: SocketAddr,
    zpr_addr: IpAddr,
    pub cn: String,
}

impl ConnectionControl {
    pub fn new() -> Self {
        ConnectionControl {}
    }

    // Must be thread safe!
    pub async fn authenticate_node(
        &self,
        _challenge_presented: &[u8],
        _timestamp: u64,
        _cn: &str,
        _challenge_response: &[u8],
    ) -> Result<NodeId, VSError> {
        // possibly blocking and cpu intensive operation...
        let res = tokio::task::spawn_blocking(move || {
            // Placeholder logic
            std::thread::sleep(std::time::Duration::from_millis(100));
            // For now, always fail.
            Err(VSError::AuthenticationFailed)
        })
        .await
        .map_err(|e| VSError::InternalError(format!("join error: {}", e)))??;

        res
    }

    // Thread safe.
    pub async fn disconnect(
        &self,
        zpr_addr: IpAddr,
        reason: vsapi::DisconnectReason,
    ) -> Result<(), VSError> {
        // Placeholder logic for disconnecting a node
        info!(target: CC, "disconnect actor at {} for reason {:?}", zpr_addr, reason);
        Ok(())
    }
}
