//! ConnectionControl is for handling new connections to the ZPRnet.
//! Nodes and adapters.  The two steps to a connection are authentication
//! and then authorization via policy.
//!
//! Nodes are authenticated using keys found in policy that are tied to
//! their CN.
//!
//! Adapters may be authenticated like nodes (using booststrap keys in policy),
//! or more commonly they will be authenticated by an authentication service
//! on th network.
//!
//! The authorization step runs through policy and attaches any special attributes
//! to the actor -- things like services offered.
//!
//! Finally, if everything goes well an address is assigned and the actor is
//! returned.

use ipnet::IpNet;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{error, info};

use libeval::actor::Actor;
use libeval::attribute::{Attribute, ROLE_NODE, key};
use libeval::eval::EvalContext;
use vsapi::vs_capnp as vsapi;

use crate::assembly::Assembly;
use crate::error::VSError;
use crate::logging::targets::CC;

pub struct ConnectionControl {
    // Placeholder for connection control data and methods
}

impl ConnectionControl {
    pub fn new() -> Self {
        ConnectionControl {}
    }

    /// Perform node specific authentication and run the connect request through policy.
    /// If successful you get an authenticated Actor back. This does not update our
    /// actor database.
    pub async fn authenticate_node(
        &self,
        asm: Arc<Assembly>,
        challenge_presented: &[u8],
        timestamp: u64,
        cn: &str,
        challenge_response: &[u8],
        remote: SocketAddr,
        node_req_addr: IpAddr,
        node_aaa_net: IpNet,
    ) -> Result<Actor, VSError> {
        // We need to be aware that the policy could be updated in the manager at any time.
        let policy = asm.policy_mgr.get_current();

        // TODO: Remove this placeholder code once we have keys in policy.
        let bootstrap_key = match policy.get_bootstrap_key_by_cn(cn) {
            Some(k) => k,
            None => return Err(VSError::AuthenticationFailed("key not found".into())),
        };

        // The node challenge response is an rsa signature of
        // concatination of (timestamp_big_endian, cn, challenge_presented)

        let mut verifier = match Verifier::new(MessageDigest::sha256(), &bootstrap_key) {
            Ok(v) => v,
            Err(e) => {
                error!(target: CC, "failed to create openssl verifier: {}", e);
                return Err(VSError::InternalError("signature processing failed".into()));
            }
        };

        let mut data = Vec::new();
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(cn.as_bytes());
        data.extend_from_slice(challenge_presented);

        verifier.update(&data).map_err(|e| {
            error!(target: CC, "failed to update openssl verifier: {}", e);
            VSError::InternalError("signature processing failed".into())
        })?;
        let sig_ok = verifier.verify(challenge_response).map_err(|_| {
            error!(target: CC, "signature verification processing failed for cn {}", cn);
            VSError::InternalError("signature processing failed".into())
        })?;
        if !sig_ok {
            info!(target: CC, "signature verification failed for cn {}", cn);
            return Err(VSError::AuthenticationFailed("invalid signature".into()));
        }

        // The policy sees everything as a bunch of claims.
        let mut authd_claims: Vec<Attribute> = Vec::new();
        authd_claims.push(Attribute::new_non_expiring(key::CN.into(), cn.to_string()));
        authd_claims.push(Attribute::new_non_expiring(
            key::SUBSTRATE_ADDR.into(),
            remote.to_string(),
        ));

        // Technically we don't know if the node claim is authenticated until it passes policy check.
        let mut unauthed_claims = HashMap::new();
        unauthed_claims.insert(key::ROLE.into(), ROLE_NODE.into());
        unauthed_claims.insert(key::ZPR_ADDR.into(), node_req_addr.to_string().into());
        unauthed_claims.insert(key::AAA_NET.into(), node_aaa_net.to_string().into());

        // Now that we have checked auth, we need to check policy.
        //
        // There may in the future be additional network I/O in the next step
        // for example if VS needs to talk to attribute service.

        let ectx = EvalContext::new(policy);

        match ectx.approve_connection(Some(&authd_claims), Some(&unauthed_claims)) {
            Ok(actor) => {
                // Make sure policy verified that the actor is in fact a node.
                if !actor.is_node() {
                    info!(target: CC, "connection not approved for cn {}: not a node", cn);
                    return Err(VSError::AuthenticationFailed("not authorized".into()));
                }
                Ok(actor)
            }
            Err(e) => {
                info!(target: CC, "connection not approved for cn {}: {}", cn, e);
                Err(e.into())
            }
        }
    }

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
