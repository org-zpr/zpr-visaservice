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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use std::usize;
use tracing::{debug, error, info, warn};

use libeval::actor::{Actor, Role};
use libeval::attribute::{Attribute, ROLE_ADAPTER, ROLE_NODE, key};
use libeval::eval::EvalContext;
use libeval::policy::Policy;

use zpr::vsapi::v1 as vsapi;
use zpr::vsapi_types::{AuthBlob, ChallengeAlg, Claim, ConnectRequest, SelfSignedBlob};

use crate::assembly::Assembly;
use crate::auth;
use crate::config;
use crate::error::VSError;
use crate::logging::targets::CC;

// TODO: move to libeval
const CLASS_ENDPOINT: &str = "endpoint";
const CLASS_USER: &str = "user";
const CLASS_SERVICE: &str = "service";

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
    ///
    /// Currently a node must pass a request address and it must match policy.
    ///
    /// This does not update our actor database, or do anything with the nodes services.
    ///
    pub async fn authenticate_node(
        &self,
        asm: Arc<Assembly>,
        challenge_presented: &[u8],
        timestamp: u64,
        cn: &str,
        challenge_response: &[u8],
        remote: SocketAddr,
        node_req_addr: IpAddr,
    ) -> Result<Actor, VSError> {
        // Grab policy here.... note that this could get updated while we are working.
        let policy = asm.policy_mgr.get_current();

        // TODO: Remove this placeholder code once we have keys in policy.
        let bootstrap_key = match policy.get_bootstrap_key_by_cn(cn) {
            Some(k) => k,
            None => return Err(VSError::AuthenticationFailed("key not found".into())),
        };

        // The node challenge response is an rsa signature of
        // concatination of (timestamp_big_endian, cn, challenge_presented)

        if !auth::verify_rsa_sha256_signature(
            bootstrap_key,
            challenge_response,
            &[&timestamp.to_be_bytes(), cn.as_bytes(), challenge_presented],
        )? {
            info!(target: CC, "signature verification failed for cn {}", cn);
            return Err(VSError::AuthenticationFailed("invalid signature".into()));
        }

        // The policy sees everything as a bunch of claims.
        let mut authd_claims: Vec<Attribute> = Vec::new();

        authd_claims.push(Attribute::builder(key::SUBSTRATE_ADDR).value(remote.to_string()));
        authd_claims.push(
            Attribute::builder(key::AUTHORITY)
                .expires(SystemTime::now() + config::DEFAULT_AUTH_EXPIRATION)
                .value(format!("fake_jwt_token:node:{cn}")),
        );

        // Technically we don't know if the node claim is authenticated until it passes policy check.
        let mut unauthd_claims = Vec::new();
        unauthd_claims.push(Attribute::builder(key::ROLE).value(ROLE_NODE));
        unauthd_claims.push(Attribute::builder(key::ZPR_ADDR).value(node_req_addr.to_string()));

        // Now that we have checked auth, we need to check policy.
        //
        // There may in the future be additional network I/O in the next step
        // for example if VS needs to talk to attribute service.

        //let ectx = EvalContext::new(policy);

        let node_actor = match self
            .authorize_connection(asm, &policy, cn, unauthd_claims, authd_claims, 0)
            .await
        {
            Ok(actor) => {
                // Make sure policy verified that the actor is in fact a node.
                if !actor.is_node() {
                    info!(target: CC, "connection not approved for cn {}: not a node", cn);
                    return Err(VSError::AuthenticationFailed("not authorized".into()));
                }
                actor
            }
            Err(e) => {
                info!(target: CC, "connection not approved for cn {}: {}", cn, e);
                return Err(e.into());
            }
        };

        Ok(node_actor)
    }

    /// Confirm adapter authentication and then get policy authorization, resulting in an Actor if
    /// everything checks out.
    pub async fn authenticate_adapter(
        &self,
        asm: Arc<Assembly>,
        req: ConnectRequest,
        connect_via: &IpAddr,
    ) -> Result<Actor, VSError> {
        if req.blobs.is_empty() || req.blobs.len() > 1 {
            return Err(VSError::ParamError("expected exactly one auth blob".into()));
        }
        check_adapter_required_claims(&req)?;
        let scrubbed_claims = scrub_adapter_claims(req.claims)?;

        let mut authd_claims = Vec::new();
        authd_claims.push(Attribute::builder(key::CONNECT_VIA).value(connect_via.to_string()));
        authd_claims
            .push(Attribute::builder(key::SUBSTRATE_ADDR).value(req.substrate_addr.to_string()));

        let adapter_actor = match &req.blobs[0] {
            AuthBlob::SS(ssb) => match ssb.alg {
                ChallengeAlg::RsaSha256Pkcs1v15 => {
                    self.authenticate_adapter_rsa(
                        asm,
                        ssb,
                        scrubbed_claims,
                        authd_claims,
                        req.dock_interface,
                    )
                    .await?
                }
            },
            AuthBlob::AC(_acb) => {
                return Err(VSError::InternalError(
                    "external auth not yet supported".into(),
                ));
            }
        };

        // Sanity check:
        if !adapter_actor.is_node() {
            warn!(target: CC, "authenticate_adapter returns a node actor: cn {}", adapter_actor.get_cn().unwrap());
            return Err(VSError::AuthenticationFailed("not an adapter".into()));
        }
        Ok(adapter_actor)
    }

    /// Preform authentication of the adapter credentials, then run through policy.
    async fn authenticate_adapter_rsa(
        &self,
        asm: Arc<Assembly>,
        ssb: &SelfSignedBlob,
        mut unauthd_claims: Vec<Attribute>,
        mut authd_claims: Vec<Attribute>,
        dock_interface: u8,
    ) -> Result<Actor, VSError> {
        // a) is the auth correct (check policy for CN, check sig.)
        // b) is connection allowed by policy?
        //
        // Note that (b) is also needed for the AC type auth.

        {
            let adapter_cn = unauthd_claims
                .iter()
                .find(|c| c.get_key() == key::CN)
                .unwrap()
                .get_single_value()
                .unwrap(); // ok becuase checked earlier

            if adapter_cn != ssb.cn {
                warn!(target: CC, "adapter cn mismatch: claim '{}' != blob '{}'", adapter_cn, ssb.cn);
                return Err(VSError::AuthenticationFailed(
                    "cn mismatch between claim and blob".into(),
                ));
            }
        }

        // Pull the public key from policy.

        let policy = asm.policy_mgr.get_current();

        let pubkey = policy.get_bootstrap_key_by_cn(&ssb.cn).ok_or_else(|| {
            VSError::AuthenticationFailed(format!("no key found in policy for cn {}", ssb.cn))
        })?;

        if !auth::verify_ss_blob_signature(&ssb.cn, ssb, pubkey)? {
            info!(target: CC, "adapter signature verification failed for cn {}", ssb.cn);
            return Err(VSError::AuthenticationFailed("invalid signature".into()));
        }

        // In prototype we make a JWT here and use that as an identity attribute.
        // TODO: implement jwt creation.

        // FAKE identity token.
        authd_claims.push(
            Attribute::builder(key::AUTHORITY)
                .expires(SystemTime::now() + config::DEFAULT_AUTH_EXPIRATION)
                .value(format!("fake_jwt_token:adapter:{}", ssb.cn)),
        );

        unauthd_claims.push(Attribute::builder(key::ROLE).value(ROLE_ADAPTER));

        // Ok checks out -- now run through policy.
        self.authorize_connection(
            asm,
            &policy,
            &ssb.cn,
            unauthd_claims,
            authd_claims,
            dock_interface,
        )
        .await
    }

    /// Use policy to authorize the adapter connection request.
    /// If successful you get an authorized Actor back.
    ///
    /// Does not alter our actor databases.
    /// May take an IP address.
    ///
    /// Caller should set ROLE in unauthd_claims before calling.
    async fn authorize_connection(
        &self,
        asm: Arc<Assembly>,
        current_policy: &Arc<Policy>,
        adapter_cn: &str,
        unauthd_claims: Vec<Attribute>,
        mut authd_claims: Vec<Attribute>,
        _dock_interface: u8,
    ) -> Result<Actor, VSError> {
        // TODO: Check with our revocation tables.
        info!(target: CC, "authorize_connection - TODO: check revocation table");
        // Actor may be denied by CN -- we can detect that before calling into policy.
        // In the future actor may be denied if the credential associated with the auth service is revoked.

        authd_claims.push(Attribute::builder(key::CN).value(adapter_cn));
        authd_claims.push(
            Attribute::builder(key::CONFIG_ID)
                .value(format!("{}", current_policy.get_version().unwrap_or(0))),
        );

        // There may in the future be additional network I/O in the next step
        // for example if VS needs to talk to attribute service.

        let ectx = EvalContext::new(current_policy.clone());

        let mut authd_actor = match ectx.approve_connection(
            Some(&authd_claims),
            Some(&unauthd_claims),
            config::DEFAULT_AUTH_EXPIRATION,
        ) {
            Ok(actor) => actor,
            Err(e) => {
                info!(target: CC, "connection not approved for cn {}: {}", adapter_cn, e);
                return Err(e.into());
            }
        };

        // Use AUTHORITY as one of the identity keys if present.
        let _ = authd_actor.add_identity_key(usize::MAX, key::AUTHORITY);

        if let Some(addr) = authd_actor.get_zpr_addr() {
            info!(target: CC, "authorized adapter cn {} with ZPR addr {}", adapter_cn, addr);
        } else {
            match asm.net_mgr.get_next_zpr_addr(Role::Adapter).await {
                Ok(addr) => {
                    authd_actor.add_attribute(
                        Attribute::builder(key::ZPR_ADDR)
                            .expires(SystemTime::now() + config::DEFAULT_AUTH_EXPIRATION)
                            .value(addr.to_string()),
                    )?;
                    info!(target: CC, "authorized adapter cn {} assigned ZPR addr {}", adapter_cn, addr);
                }
                Err(e) => {
                    error!(target: CC, "failed to assign ZPR addr to authorized adapter cn {}: {}", adapter_cn, e);
                    return Err(VSError::InternalError("address assignment failed".into()));
                }
            }
        }

        Ok(authd_actor)
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
                if let Some(vss_hndl) = asm.vss_mgr.get_handle(&zpr_addr) {
                    if let Err(e) = vss_hndl.stop().await {
                        error!(target: CC, "failed to stop VSS worker for disconnected node at addr {zpr_addr}: {}", e);
                    }
                } else {
                    debug!(target: CC, "no VSS worker found for disconnected node at addr {zpr_addr}");
                }
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
                    if let Err(s) = asm.net_mgr.release_zpr_addr(adapter_addr).await {
                        error!(target: CC, "failed to release ZPR addr {adapter_addr} for orphaned adapter: {}", s);
                    }
                }
                asm.actor_mgr.remove_node(&zpr_addr).await?;
                asm.visa_mgr.remove_visas_for_node(&zpr_addr).await?;
            }
        }

        if let Err(e) = asm
            .visa_mgr
            .remove_visas_for_actors(&removed_zpr_addrs)
            .await
        {
            error!(target: CC, "failed to remove visas for disconnected actor at addr {zpr_addr}: {}", e);
        }

        asm.net_mgr.release_zpr_addr(zpr_addr).await?;

        Ok(())
    }
}

/// Check that required claims are present, or return an error.
///
/// Only required claim is CN.
fn check_adapter_required_claims(req: &ConnectRequest) -> Result<(), VSError> {
    let mut cn_found = false;
    for c in &req.claims {
        if c.key == key::CN {
            if c.value.is_empty() {
                return Err(VSError::ParamError("cn claim cannot be empty".into()));
            }
            cn_found = true;
            break;
        }
    }
    if !cn_found {
        return Err(VSError::ParamError("cn claim is required".into()));
    }
    Ok(())
}

// Gatekeep claims. Claims are considered to be adapter _requests_ which may
// or may not be honored by policy.  But we set attributes from them and need
// and some are for internal use only.
//
// Generally no claims that start with "zpr." are allowed except:
//   - zpr.addr -> which is interpreted as a request adapter ZPR address.
//
// Also cannot have <class>.zpr.* except:
//   - endpoint.zpr.adapter.cn -> which is the CN of the adapter as told to the node.
//
// Note classes are endpoint, user, service (as per ZPL and the compiler).
//
// Finally, the incoming VSAPI "Claims" are converted into libeval "Attributes" and returned.
fn scrub_adapter_claims(claims: Vec<Claim>) -> Result<Vec<Attribute>, VSError> {
    let mut scrubbed_claims = Vec::new();
    for claim in claims {
        if claim.key == key::ZPR_ADDR {
            // Allow zpr.addr
            scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
            continue;
        }

        if claim.key.starts_with("zpr.") {
            warn!(target: CC, "adapter claim key '{}' not allowed", claim.key);
            continue;
        }

        let parts: Vec<&str> = claim.key.split('.').collect();
        if parts.len() >= 2 && parts[1] == "zpr" {
            // Only permissible is endpoint.zpr.adapter.cn
            if claim.key == key::CN {
                // Allow endpoint.zpr.adapter.cn
                scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
                continue;
            }

            // We only check for the defined classes.
            if parts[0] == CLASS_ENDPOINT || parts[0] == CLASS_USER || parts[0] == CLASS_SERVICE {
                warn!(target: CC, "adapter claim key '{}' not allowed", claim.key);
                continue;
            }
        }

        // Note that we don't handle multi-value claims at this point.
        scrubbed_claims.push(Attribute::builder(claim.key).value(claim.value));
    }
    Ok(scrubbed_claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(key: &str, value: &str) -> Claim {
        Claim::new(key.to_string(), value.to_string())
    }

    fn keys(claims: &[Attribute]) -> Vec<String> {
        claims
            .iter()
            .map(|claim| claim.get_key().to_string())
            .collect()
    }

    #[test]
    fn scrub_adapter_claims_allows_addr_and_cn() {
        let claims = vec![
            claim(key::ZPR_ADDR, "fd5a:5052:90de::1"),
            claim(key::CN, "adapter.example"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::ZPR_ADDR, key::CN]);
    }

    #[test]
    fn scrub_adapter_claims_blocks_zpr_prefix_except_addr() {
        let claims = vec![
            claim("zpr.role", "adapter"),
            claim("zpr.services", "svc-a"),
            claim(key::ZPR_ADDR, "fd5a:5052:90de::2"),
            claim("endpoint.label", "edge"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::ZPR_ADDR, "endpoint.label"]);
    }

    #[test]
    fn scrub_adapter_claims_blocks_class_zpr_for_known_classes() {
        let claims = vec![
            claim("endpoint.zpr.adapter.token", "nope"),
            claim("user.zpr.name", "nope"),
            claim("service.zpr.name", "nope"),
            claim(key::CN, "allowed-cn"),
            claim("custom.zpr.value", "ok"),
        ];

        let scrubbed = scrub_adapter_claims(claims).expect("scrub should succeed");

        assert_eq!(keys(&scrubbed), vec![key::CN, "custom.zpr.value"]);
    }
}
