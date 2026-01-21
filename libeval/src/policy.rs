use std::collections::HashMap;
use std::io::Error as IoError;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use openssl::pkey::{PKey, Public};
use thiserror::Error;

use crate::attribute::Attribute;
use crate::joinpolicy::JPolicy;

use zpr::policy::v1 as policy_capnp;
use zpr::policy_types::{PolicyTypeError, Service};

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
    serialized: Bytes,
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

        let bootstrap_keys = Self::load_bootstrap_keys(&Policy::default(), &policy)?;
        let join_policies = Self::load_join_policies(&Policy::default(), &policy)?;
        let services = Self::load_services(&Policy::default(), &policy)?;

        Ok(Policy {
            policy_rdr: Some(Arc::new(policy_reader)),
            bootstrap_keys,
            join_policies,
            services,
            serialized,
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

    fn load_bootstrap_keys(
        &self,
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
    fn load_join_policies(
        &self,
        policy: &policy_capnp::policy::Reader,
    ) -> Result<Vec<JPolicy>, PolicyError> {
        let mut join_policies: Vec<JPolicy> = Vec::new();
        if policy.has_join_policies() {
            for jp_rdr in policy.get_join_policies()?.iter() {
                let jp = JPolicy::try_from(jp_rdr)?;
                join_policies.push(jp);
            }
        }
        Ok(join_policies)
    }

    // Load (cache) the set of services found in the binary policy object. The services are
    // stored in binary policy as part of the join policies but our join-policy loader doesn't
    // fully load them since it doesn't need to.
    fn load_services(
        &self,
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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pio::{Version, load_policy};
    use std::env;
    use std::path::PathBuf;

    const MIN_COMPILER_VERSION: Version = Version(0, 9, 2);

    fn read_policy_from_test_file(filename: &str) -> Policy {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let fpath = PathBuf::from(manifest_dir).join("test-data").join(filename);
        load_policy(&fpath, MIN_COMPILER_VERSION).unwrap()
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
}
