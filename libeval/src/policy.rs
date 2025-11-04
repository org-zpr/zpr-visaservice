use std::collections::HashMap;
use std::io::Error as IoError;
use std::sync::Arc;

use bytes::Bytes;
use openssl::pkey::{PKey, Public};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("Invalid policy format: {0}")]
    InvalidFormat(String),
}

#[derive(Default)]
pub struct Policy {
    /// Buffer containing the encoded policy, if present
    policy_rdr: Option<Arc<capnp::message::Reader<capnp::serialize::OwnedSegments>>>,
    vinst: u64,
    bootstrap_keys: HashMap<String, PKey<Public>>,
}

impl Policy {
    pub fn new_empty(vinst: u64) -> Self {
        Policy {
            vinst,
            ..Default::default()
        }
    }

    /// Pass a v2 format encoded Policy struct here. This can be found inside a PolicyContainer.
    pub fn new_from_policy_bytes(
        vinst: u64,
        encoded_policy_bytes: Bytes,
    ) -> Result<Self, PolicyError> {
        // parse the policy bytes using capnp
        let policy_reader = capnp::serialize::read_message(
            &mut std::io::Cursor::new(&encoded_policy_bytes),
            capnp::message::ReaderOptions::new(),
        )?;
        Ok(Policy {
            policy_rdr: Some(Arc::new(policy_reader)),
            vinst,
            ..Default::default()
        })
    }

    pub fn get_policy_reader(
        &self,
    ) -> Option<Arc<capnp::message::Reader<capnp::serialize::OwnedSegments>>> {
        self.policy_rdr.clone()
    }

    /// The vinst (version instance) is incremented each time the policy is changed.
    pub fn get_vinst(&self) -> u64 {
        self.vinst
    }

    pub fn get_bootstrap_key_by_cn(&self, cn: &str) -> Option<PKey<Public>> {
        self.bootstrap_keys.get(cn).cloned()
    }
}
