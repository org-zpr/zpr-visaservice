use crate::error::PioError;
use bytes::{Buf, Bytes};
use libeval::policy::Policy;
use std::path::Path;
use zpr::policy::v1 as policy_capnp;

pub fn load_policy(path: &Path) -> Result<Policy, PioError> {
    let encoded = std::fs::read(path)?;
    let encoded_container_bytes = Bytes::from(encoded);

    // The v2 binary format wraps a Policy struct inside a PolicyContainer struct.
    let container_reader = capnp::serialize::read_message(
        encoded_container_bytes.reader(),
        capnp::message::ReaderOptions::new(),
    )?;

    let container = container_reader.get_root::<policy_capnp::policy_container::Reader>()?;

    // TODO: check compiler version?
    // TODO: check signature?

    if !container.has_policy() {
        return Err(PioError::InvalidFormat(
            "policy container missing 'policy' field".to_string(),
        ));
    }
    let policy_bytes = container.get_policy().unwrap();
    let zp = Policy::new_from_policy_bytes(Bytes::copy_from_slice(policy_bytes))?;
    Ok(zp)
}
