use crate::error::PioError;
use ::polio::policy_capnp;
use bytes::Bytes;
use libeval::zpr_policy::ZprPolicy;
use std::path::Path;

pub fn load_policy(path: &Path) -> Result<ZprPolicy, PioError> {
    let encoded = std::fs::read(path)?;
    let encoded_container_bytes = Bytes::from(encoded);

    // The v2 binary format wraps a Policy struct inside a PolicyContainer struct.
    let container_reader = capnp::serialize::read_message(
        &mut std::io::Cursor::new(&encoded_container_bytes),
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
    let zp = ZprPolicy::new_from_policy_bytes(Bytes::copy_from_slice(policy_bytes))?;
    Ok(zp)
}
