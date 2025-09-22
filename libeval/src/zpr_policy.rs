use ::polio::policy_capnp;

use bytes::Bytes;
use std::io::Error as IoError;
use std::path::Path;
use thiserror::Error;

use crate::eval::EvalDecision;
use crate::{Actor, PacketDesc};

#[derive(Debug, Error)]
pub enum ZprPolicyError {
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("Invalid policy format: {0}")]
    InvalidFormat(String),
}

pub struct ZprPolicy {
    /// Buffer containing the encoded policy.
    policy_rdr: capnp::message::Reader<capnp::serialize::OwnedSegments>,
}

impl ZprPolicy {
    pub fn new_from_file(path: &Path) -> Result<Self, ZprPolicyError> {
        let encoded = std::fs::read(path)?;
        let encoded_buf = Bytes::from(encoded);
        Self::new_from_container_bytes(encoded_buf)
    }

    /// The v2 binary format wraps a Policy struct inside a PolicyContainer struct.
    /// Pass the container bytes here.
    pub fn new_from_container_bytes(
        encoded_container_bytes: Bytes,
    ) -> Result<Self, ZprPolicyError> {
        // parse the encoded bytes using capnp
        let container_reader = capnp::serialize::read_message(
            &mut std::io::Cursor::new(&encoded_container_bytes),
            capnp::message::ReaderOptions::new(),
        )?;

        let container = container_reader.get_root::<policy_capnp::policy_container::Reader>()?;

        // TODO: check compiler version?
        // TODO: check signature?

        if !container.has_policy() {
            return Err(ZprPolicyError::InvalidFormat(
                "Policy container missing 'policy' field".to_string(),
            ));
        }
        let policy_bytes = container.get_policy().unwrap();
        Self::new_from_policy_bytes(Bytes::copy_from_slice(policy_bytes))
    }

    /// Pass a v2 format encoded Policy struct here. This can be found inside a PolicyContainer.
    pub fn new_from_policy_bytes(encoded_policy_bytes: Bytes) -> Result<Self, ZprPolicyError> {
        // parse the policy bytes using capnp
        let policy_reader = capnp::serialize::read_message(
            &mut std::io::Cursor::new(&encoded_policy_bytes),
            capnp::message::ReaderOptions::new(),
        )?;
        //let policy = policy_reader.get_root::<policy_capnp::policy::Reader>()?;

        Ok(ZprPolicy {
            policy_rdr: policy_reader,
        })
    }

    pub fn eval_request(
        &self,
        _src_actor: &Actor,
        _dst_actor: &Actor,
        _request: &PacketDesc,
    ) -> Result<EvalDecision, ZprPolicyError> {
        let policy = self.policy_rdr.get_root::<policy_capnp::policy::Reader>()?;
        if !policy.has_com_policies() {
            return Ok(EvalDecision::NoMatch(
                "no communication policies defined".into(),
            ));
        }
        Ok(EvalDecision::NoMatch("not implemented".into()))
    }
}
