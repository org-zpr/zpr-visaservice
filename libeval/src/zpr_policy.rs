use bytes::Bytes;
use std::io::Error as IoError;
use thiserror::Error;

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
    pub policy_rdr: capnp::message::Reader<capnp::serialize::OwnedSegments>,
}

impl ZprPolicy {
    /// Pass a v2 format encoded Policy struct here. This can be found inside a PolicyContainer.
    pub fn new_from_policy_bytes(encoded_policy_bytes: Bytes) -> Result<Self, ZprPolicyError> {
        // parse the policy bytes using capnp
        let policy_reader = capnp::serialize::read_message(
            &mut std::io::Cursor::new(&encoded_policy_bytes),
            capnp::message::ReaderOptions::new(),
        )?;
        Ok(ZprPolicy {
            policy_rdr: policy_reader,
        })
    }
}
