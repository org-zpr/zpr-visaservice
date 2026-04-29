use std::collections::HashMap;
use std::io::Error as IoError;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use openssl::pkey::{PKey, Public};
use thiserror::Error;

use crate::attribute::Attribute;
use crate::joinpolicy::JPolicy;

use zpr::policy::v1 as policy_capnp;
use zpr::policy_types::{AttrExp, NetAddr, Peering, PolicyTypeError, Service, ServiceType};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("i/o error: {0}")]
    Io(#[from] IoError),

    #[error("cap'n proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("cap'n proto not-in-shchema error: {0}")]
    CapnpNotInSchema(#[from] capnp::NotInSchema),

    #[error("invalid policy format: {0}")]
    InvalidFormat(String),

    #[error("UTF8 encoding error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("openssl error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    #[error("policy file error: {0}")]
    PolicyFileError(String),

    #[error("policy version error: {0}")]
    PolicyVersionError(String),

    #[error("policy type error: {0}")]
    PolicyTypeError(#[from] PolicyTypeError),
}

#[derive(Default)]
pub struct Policy {
    /// Buffer containing the encoded policy, if present
    policy_rdr: Option<Arc<capnp::message::Reader<capnp::serialize::OwnedSegments>>>,
    vinst: u64,
    bootstrap_keys: HashMap<String, PKey<Public>>,
    join_policies: Vec<JPolicy>,
    services: HashMap<String, Service>,
    cpol_sources: Vec<String>,
    serialized: Bytes,
    peer_table: Option<HashMap<IpAddr, Vec<Peer>>>, // zpr_addr -> peers
    link_attrs: Option<HashMap<String, Vec<AttrExp>>>, // link_id -> attributes
}

/// A "Peer" is a one way view of a link. This is the remote substrate address from the persective
/// of one of the ends. See [Policy::get_peers_for_node].
#[derive(Debug, Clone)]
pub struct Peer {
    /// Each link has an identifier set in compiler. Used for debugging, and in policy here this is
    /// used to get the link attributes.
    ///
    /// See [Policy::get_link_attrs].
    pub peer_id: String,

    /// Note that a [NetAddr] may require a DNS lookup to resolve.
    pub remote_substrate: NetAddr,
}

impl Policy {
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Pass a v2 format encoded Policy struct here. This can be found inside a PolicyContainer.
    pub fn new_from_policy_bytes(encoded_policy_bytes: Bytes) -> Result<Self, PolicyError> {
        // Keep a copy of the bytes so we can make it avaialbe for storage.
        // TODO: Do we actually want the whole container?
        let serialized = encoded_policy_bytes.clone();

        // parse the policy bytes using capnp
        let policy_reader = capnp::serialize::read_message(
            encoded_policy_bytes.reader(),
            capnp::message::ReaderOptions::new(),
        )?;

        let policy = policy_reader.get_root::<policy_capnp::policy::Reader>()?;

        let bootstrap_keys = load_bootstrap_keys(&policy)?;
        let join_policies = load_join_policies(&policy)?;
        let services = load_services(&policy)?;
        let cpol_sources = load_cpol_sources(&policy)?;
        let peerings = load_peerings(&policy)?;

        let peer_table = if let Some(ref peerings) = peerings {
            // We have links defined in policy. Organize into useful lookup table for visa service.
            let mut table: HashMap<IpAddr, Vec<Peer>> = HashMap::new();
            for p in peerings {
                // Each "Peering" is an edge with two endpoints. We create entries in our peer table
                // for each endpoint.
                //
                let peer_a_to_b = Peer {
                    peer_id: p.link_id.clone(),
                    remote_substrate: p.substrate_a.clone(),
                };
                table
                    .entry(p.node_a)
                    .or_insert_with(Vec::new)
                    .push(peer_a_to_b);

                let peer_b_to_a = Peer {
                    peer_id: p.link_id.clone(),
                    remote_substrate: p.substrate_b.clone(),
                };
                table
                    .entry(p.node_b)
                    .or_insert_with(Vec::new)
                    .push(peer_b_to_a);
            }
            Some(table)
        } else {
            None
        };
        let link_attrs = if let Some(ref peerings) = peerings {
            let mut table: HashMap<String, Vec<AttrExp>> = HashMap::new();
            for p in peerings {
                if !p.attributes.is_empty() {
                    table.insert(p.link_id.clone(), p.attributes.clone());
                }
            }
            Some(table)
        } else {
            None
        };

        Ok(Policy {
            policy_rdr: Some(Arc::new(policy_reader)),
            bootstrap_keys,
            join_policies,
            services,
            cpol_sources,
            serialized,
            peer_table,
            link_attrs,
            ..Default::default()
        })
    }

    pub fn get_policy_reader(
        &self,
    ) -> Option<Arc<capnp::message::Reader<capnp::serialize::OwnedSegments>>> {
        self.policy_rdr.clone()
    }

    pub fn get_serialized(&self) -> &Bytes {
        &self.serialized
    }

    pub fn vinst(&self) -> u64 {
        self.vinst
    }

    /// Set the "installed version". This is here to support the visa service which
    /// increments the vinst each time a new policy is installed. This should not
    /// be called by other users of policy.
    pub fn set_vinst(&mut self, vinst: u64) {
        self.vinst = vinst;
    }

    /// The vinst (version instance) is incremented each time the policy is changed.
    pub fn get_vinst(&self) -> u64 {
        self.vinst
    }

    /// Return all join policies that match the given attributes.
    pub fn match_join_policies(&self, attrs: &[Attribute]) -> Vec<&JPolicy> {
        let mut matched_policies: Vec<&JPolicy> = Vec::new();

        for jp in &self.join_policies {
            if jp.matches(attrs) {
                matched_policies.push(jp);
            }
        }
        matched_policies
    }

    pub fn get_bootstrap_key_by_cn(&self, cn: &str) -> Option<PKey<Public>> {
        self.bootstrap_keys.get(cn).cloned()
    }

    /// Get the created timestamp string from the policy, if present.
    pub fn get_created(&self) -> Option<&str> {
        if let Some(policy_rdr) = &self.policy_rdr {
            if let Ok(policy) = policy_rdr.get_root::<policy_capnp::policy::Reader>() {
                if let Ok(created) = policy.get_created() {
                    return created.to_str().ok();
                }
            }
        }
        None
    }

    /// Get the version number from the policy, if present.
    pub fn get_version(&self) -> Option<u64> {
        if let Some(policy_rdr) = &self.policy_rdr {
            if let Ok(policy) = policy_rdr.get_root::<policy_capnp::policy::Reader>() {
                return Some(policy.get_version());
            }
        }
        None
    }

    /// Get the metadata string from the policy, if present.
    pub fn get_metadata(&self) -> Option<&str> {
        if let Some(policy_rdr) = &self.policy_rdr {
            if let Ok(policy) = policy_rdr.get_root::<policy_capnp::policy::Reader>() {
                if let Ok(metadata) = policy.get_metadata() {
                    match metadata.to_str() {
                        Ok(s) => return Some(s),
                        Err(_) => return None,
                    }
                }
            }
        }
        None
    }

    /// List all services defined in this policy.
    pub fn list_services(&self) -> Vec<&Service> {
        self.services.values().collect()
    }

    /// List all services defined in this policy that have the indicated `kind`.
    pub fn list_services_by_kind(&self, kind: ServiceType) -> Vec<&Service> {
        self.services
            .values()
            .filter(|svc| svc.kind == kind)
            .collect()
    }

    /// Get the ZPL source for the communication policy by policy index.
    pub fn get_cpol_source(&self, idx: usize) -> Option<&str> {
        self.cpol_sources.get(idx).map(|s| s.as_str())
    }

    /// Pass the node ZPR address to get the list of peers (if any).
    pub fn get_peers_for_node(&self, node_zpr_addr: &IpAddr) -> Option<&Vec<Peer>> {
        self.peer_table.as_ref()?.get(node_zpr_addr)
    }

    /// A link may have attributes on it, this returns them.
    pub fn get_link_attrs(&self, link_id: &str) -> Option<&Vec<AttrExp>> {
        self.link_attrs.as_ref()?.get(link_id)
    }
}

fn load_bootstrap_keys(
    policy: &policy_capnp::policy::Reader,
) -> Result<HashMap<String, PKey<Public>>, PolicyError> {
    let mut bootstrap_keys: HashMap<String, PKey<Public>> = HashMap::new();
    if policy.has_keys() {
        for key in policy.get_keys()?.iter() {
            // Only take the key if it is for bootstrap.
            let allows = key.get_key_allows()?;
            for allowance in allows.iter() {
                if let Ok(aw) = allowance {
                    if aw == policy_capnp::KeyAllowance::Bootstrap {
                        let cn = key.get_id()?.to_string()?;
                        if key.get_key_type()? != policy_capnp::KeyMaterialT::RsaPub {
                            return Err(PolicyError::InvalidFormat(format!(
                                "Unsupported key type in bootstrap key for cn '{cn}': {:?}",
                                key.get_key_type()?
                            )));
                        }
                        let key_der = key.get_key_data()?;
                        let pkey = PKey::public_key_from_der(&key_der)?;
                        bootstrap_keys.insert(cn.to_string(), pkey);
                    }
                }
            }
        }
    }
    Ok(bootstrap_keys)
}

// Load (cache) the set of join policies found in the binary policy object.
fn load_join_policies(policy: &policy_capnp::policy::Reader) -> Result<Vec<JPolicy>, PolicyError> {
    let mut join_policies: Vec<JPolicy> = Vec::new();
    if policy.has_join_policies() {
        for jp_rdr in policy.get_join_policies()?.iter() {
            let jp = JPolicy::try_from(jp_rdr)?;
            join_policies.push(jp);
        }
    }
    Ok(join_policies)
}

fn load_cpol_sources(policy: &policy_capnp::policy::Reader) -> Result<Vec<String>, PolicyError> {
    let mut cpol_sources = Vec::new();
    if policy.has_com_policies() {
        for cp_rdr in policy.get_com_policies()?.iter() {
            let zpl = cp_rdr.get_zpl()?.to_string()?;
            cpol_sources.push(zpl);
        }
    }
    Ok(cpol_sources)
}

// Load (cache) the set of services found in the binary policy object. The services are
// stored in binary policy as part of the join policies but our join-policy loader doesn't
// fully load them since it doesn't need to.
fn load_services(
    policy: &policy_capnp::policy::Reader,
) -> Result<HashMap<String, Service>, PolicyError> {
    let mut services = HashMap::new();
    if policy.has_join_policies() {
        for jp_rdr in policy.get_join_policies()?.iter() {
            if jp_rdr.has_provides() {
                for svc_rdr in jp_rdr.get_provides()?.iter() {
                    let svc = Service::try_from(svc_rdr)?;
                    if let Some(previous) = services.insert(svc.id.clone(), svc) {
                        return Err(PolicyError::InvalidFormat(format!(
                            "duplicate service id in policy: {}",
                            previous.id
                        )));
                    }
                }
            }
        }
    }
    Ok(services)
}

fn load_peerings(
    policy: &policy_capnp::policy::Reader,
) -> Result<Option<Vec<Peering>>, PolicyError> {
    if policy.has_topology() {
        let mut peerings = Vec::new();
        for peer_rdr in policy.get_topology()?.iter() {
            let peering = Peering::try_from(peer_rdr)?;
            peerings.push(peering);
        }
        Ok(Some(peerings))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pio::{Version, load_policy};
    use std::env;
    use std::path::PathBuf;

    use zpr::policy::v1 as policy_capnp;

    const MIN_COMPILER_VERSION: Version = Version(0, 9, 2);

    fn read_policy_from_test_file(filename: &str) -> Policy {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let fpath = PathBuf::from(manifest_dir).join("test-data").join(filename);
        load_policy(&fpath, MIN_COMPILER_VERSION).unwrap()
    }

    /// Build a Policy from a list of ZPL source strings by constructing a capnp
    /// policy message in memory, without needing a compiled policy file.
    fn policy_with_cpol_sources(zpls: &[&str]) -> Policy {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut policy = msg.init_root::<policy_capnp::policy::Builder>();
            let mut coms = policy.reborrow().init_com_policies(zpls.len() as u32);
            for (i, zpl) in zpls.iter().enumerate() {
                coms.reborrow().get(i as u32).set_zpl(zpl);
            }
        }
        let mut bytes: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut bytes, &msg).unwrap();
        Policy::new_from_policy_bytes(Bytes::from(bytes)).unwrap()
    }

    #[test]
    fn test_get_boostrap_key_by_cn_not_there() {
        let policy = Policy::new_empty();
        let key = policy.get_bootstrap_key_by_cn("nonexistent");
        assert!(key.is_none());
    }

    #[test]
    fn test_get_bootstrap_key() {
        let policy = read_policy_from_test_file("test-keys.bin2");

        // not there:
        let key = policy.get_bootstrap_key_by_cn("nonexistant");
        assert!(key.is_none());

        let cns = vec!["node.zpr.org", "foo.fee", "haha.very.funny"];
        for cn in cns {
            let key = policy.get_bootstrap_key_by_cn(cn);
            assert!(
                key.is_some(),
                "expected to find bootstrap key for cn '{cn}'"
            );
        }
    }

    #[test]
    /// get_cpol_source returns the expected ZPL string for known indices when the
    /// policy contains communication policies.
    fn test_get_cpol_source_returns_zpl_for_known_index() {
        let zpls = ["allow all traffic.", "deny all traffic."];
        let policy = policy_with_cpol_sources(&zpls);

        assert_eq!(policy.get_cpol_source(0), Some("allow all traffic."));
        assert_eq!(policy.get_cpol_source(1), Some("deny all traffic."));
    }

    #[test]
    /// get_cpol_source returns None when the requested index is out of bounds.
    fn test_get_cpol_source_out_of_bounds_returns_none() {
        let zpls = ["allow all traffic."];
        let policy = policy_with_cpol_sources(&zpls);

        assert!(policy.get_cpol_source(1).is_none());
        assert!(policy.get_cpol_source(99).is_none());
    }

    #[test]
    /// get_cpol_source returns None for any index on an empty policy that has no
    /// communication policies.
    fn test_get_cpol_source_empty_policy_returns_none() {
        let policy = Policy::new_empty();

        assert!(policy.get_cpol_source(0).is_none());
    }
}
