use std::collections::HashMap;
use std::io::Error as IoError;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use openssl::pkey::{PKey, Public};
use thiserror::Error;

use polio::policy_capnp;

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
}

#[derive(Default)]
pub struct Policy {
    /// Buffer containing the encoded policy, if present
    policy_rdr: Option<Arc<capnp::message::Reader<capnp::serialize::OwnedSegments>>>,
    vinst: u64,
    bootstrap_keys: HashMap<String, PKey<Public>>,
}

impl Policy {
    pub fn new_empty() -> Self {
        Self::default()
    }

    /// Pass a v2 format encoded Policy struct here. This can be found inside a PolicyContainer.
    pub fn new_from_policy_bytes(encoded_policy_bytes: Bytes) -> Result<Self, PolicyError> {
        // parse the policy bytes using capnp
        let policy_reader = capnp::serialize::read_message(
            encoded_policy_bytes.reader(),
            capnp::message::ReaderOptions::new(),
        )?;

        let policy = policy_reader.get_root::<policy_capnp::policy::Reader>()?;

        let bootstrap_keys = Self::load_bootstrap_keys(&Policy::default(), &policy)?;
        Ok(Policy {
            policy_rdr: Some(Arc::new(policy_reader)),
            bootstrap_keys,
            ..Default::default()
        })
    }

    pub fn get_policy_reader(
        &self,
    ) -> Option<Arc<capnp::message::Reader<capnp::serialize::OwnedSegments>>> {
        self.policy_rdr.clone()
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

    pub fn get_bootstrap_key_by_cn(&self, cn: &str) -> Option<PKey<Public>> {
        self.bootstrap_keys.get(cn).cloned()
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
