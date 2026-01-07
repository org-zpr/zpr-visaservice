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
use std::time::{Duration, SystemTime};
use tracing::{error, info, warn};

use libeval::actor::Actor;
use libeval::attribute::{Attribute, ROLE_NODE, key};
use libeval::eval::EvalContext;
use zpr::vsapi::v1 as vsapi;

use crate::assembly::Assembly;
use crate::config;
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
        authd_claims.push(Attribute::builder(key::CN).value(cn));
        authd_claims.push(Attribute::builder(key::SUBSTRATE_ADDR).value(remote.to_string()));

        // Technically we don't know if the node claim is authenticated until it passes policy check.
        let mut unauthed_claims = HashMap::new();
        unauthed_claims.insert(key::ROLE.into(), ROLE_NODE.into());

        // The node may request an address. It will get this address only if policy does
        // not assign it a different one.
        // TODO: VS must check later to see if this address is in use or even valid.
        unauthed_claims.insert(key::ZPR_ADDR.into(), node_req_addr.to_string().into());

        // The AAA net stuff is not under control of libeval.
        // The visa service needs to manage the AAA_NET info and ensure that nodes are
        // non-overlapping.  No need to pass this to libeval.
        // TODO: VS must check and track this value.
        unauthed_claims.insert(key::AAA_NET.into(), node_aaa_net.to_string().into());

        // Now that we have checked auth, we need to check policy.
        //
        // There may in the future be additional network I/O in the next step
        // for example if VS needs to talk to attribute service.

        let ectx = EvalContext::new(policy);

        match ectx.approve_connection(
            Some(&authd_claims),
            Some(&unauthed_claims),
            Duration::from_secs(config::DEFAULT_EXPIRATION_SECONDS),
        ) {
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

        // Things remaining to do here:
        //
        // (1) ZPR ADDRESS
        //
        // VS assigns and tracks addresses. Connection policy could set a static address
        // for the node. If so, the ZPR_ADDR will be present on the actor. In this case
        // we need to check that the addr hasn't already been assigned to another actor.
        // (And if so, do we remove the other actor?)
        //
        // If the actor does not have a ZPR_ADDR attribute, then VS needs to assign one.
        // If the node requested an address, we should try to give it that one if possible.
        // Otherwise we need to pick one from the available pool.
        //
        // (2) AAA NET
        //
        // We got the nodes requested AAA network. I don't think we have a way to tell the
        // node to use a different one. So we need to check here that that AAA net is
        // not already in use. We need to track that this new AAA net is now in use.
        //
        // (3) SERVICES
        //
        // The actor may provide services. We need to register those somewhere. The actor
        // will just have service IDs. We'll need to check policy to get the endpoint
        // details if needed. Note that addition of auth services and trusted services
        // requires more work too.
        //
    }

    /// Disconnect logic. Cleans up actor database and visas.
    pub async fn disconnect(
        &self,
        asm: Arc<Assembly>,
        zpr_addr: IpAddr,
        reason: vsapi::DisconnectReason,
    ) -> Result<(), VSError> {
        info!(target: CC, "disconnect actor at {} for reason {:?}", zpr_addr, reason);

        let maybe_actor = asm.actor_mgr.get_actor_by_zpr_addr(&zpr_addr).await?;
        if maybe_actor.is_none() {
            warn!(target: CC, "disconnect for addr {zpr_addr} but no actor found in database");
        }

        match asm.actor_mgr.remove_actor_by_zpr_addr(&zpr_addr).await {
            Ok(()) => (),
            Err(e) => {
                // Caller can't do anything with this. So just log and continue.
                error!(target: CC, "failed to remove disconnected actor with addr {zpr_addr} from actor db: {}", e);
            }
        };

        let mut removed_zpr_addrs = Vec::new();
        removed_zpr_addrs.push(zpr_addr);

        if let Some(actor) = maybe_actor {
            if actor.is_node() {
                let connected_adapters = match asm
                    .actor_mgr
                    .get_adapters_connected_to_node(&zpr_addr)
                    .await
                {
                    Ok(addrs) => addrs,
                    Err(e) => {
                        error!(target: CC, "failed to get connected adapters for disconnected node at addr {zpr_addr}: {}", e);
                        Vec::new()
                    }
                };
                for adapter_addr in connected_adapters {
                    match asm.actor_mgr.remove_actor_by_zpr_addr(&adapter_addr).await {
                        Ok(()) => {
                            removed_zpr_addrs.push(adapter_addr);
                        }
                        Err(e) => {
                            // Caller can't do anything with this. So just log and continue.
                            error!(target: CC, "failed to remove disconnected adapter with addr {adapter_addr} from actor db: {}", e);
                        }
                    };
                }
                asm.actor_mgr.remove_node(&zpr_addr).await?;
                asm.visa_mgr.remove_visas_for_node(&zpr_addr).await?;
            }
        }

        asm.visa_mgr
            .remove_visas_for_actors(&removed_zpr_addrs)
            .await?;

        Ok(())
    }
}
