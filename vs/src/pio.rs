use bytes::Bytes;
use libeval::policy::Policy;
use std::fmt;
use std::path::Path;
use tracing::info;

use ::polio::policy_capnp;

use crate::error::VSError;
use crate::logging::targets::POLICY;

/// (Major, Minor, Patch)
#[derive(Debug)]
pub struct Version(pub u32, pub u32, pub u32);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// Load policy from file. Checks the version of the compiler against the passed
/// minimum version.  This will not allow loading policies if the major version
/// is not the same as specified in the minimum version.
pub fn load_policy(fpath: &Path, min_version: Version) -> Result<Policy, VSError> {
    let encoded = std::fs::read(fpath)?;
    let encoded_container_bytes = Bytes::from(encoded);

    let container_reader = capnp::serialize::read_message(
        &mut std::io::Cursor::new(&encoded_container_bytes),
        capnp::message::ReaderOptions::new(),
    )?;

    let container = container_reader.get_root::<policy_capnp::policy_container::Reader>()?;

    // Version check: container compiler major version must be >= min_version.major

    let comp_version = Version(
        container.get_zplc_ver_major(),
        container.get_zplc_ver_minor(),
        container.get_zplc_ver_patch(),
    );

    if (comp_version.0 < min_version.0) || (comp_version.0 > min_version.0) {
        return Err(VSError::PolicyVersionError(format!(
            "policy file major version {comp_version} is not compatible with the expected version {min_version}",
        )));
    }
    if comp_version.0 == min_version.0 {
        if comp_version.1 < min_version.1 {
            return Err(VSError::PolicyVersionError(format!(
                "policy file minor version {comp_version} is less than required minimum {min_version}",
            )));
        } else if comp_version.1 == min_version.1 {
            if comp_version.2 < min_version.2 {
                return Err(VSError::PolicyVersionError(format!(
                    "policy file patch version {comp_version} is less than required minimum {min_version}",
                )));
            }
        }
    }

    if !container.has_policy() {
        return Err(VSError::PolicyFileError(
            "policy container missing policy data".to_string(),
        ));
    }

    let policy_bytes = container.get_policy().unwrap();
    let p = Policy::new_from_policy_bytes(Bytes::copy_from_slice(policy_bytes))?;
    info!(target: POLICY, "loaded policy created by compiler version {comp_version}");
    Ok(p)
}
