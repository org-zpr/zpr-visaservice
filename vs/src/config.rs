//! Structs that map to the TOML configuration file for the visa service.

use serde::Deserialize;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use crate::error::VSError;
use crate::zpr;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct VSConfig {
    pub core: CoreSection,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct CoreSection {
    /// The visa service bind address - this is a constant baked into entire ZPR system only override for testing.
    pub vs_addr: Option<IpAddr>,

    /// VSAPI port used by nodes to talk to the visa service VSS API.
    /// Must be kept in sync with the compiler.
    pub vsapi_port: Option<u16>,

    /// HTTPS Admin port used to control the visa service.
    /// Must be kept in sync with the compiler.
    pub admin_port: Option<u16>,

    /// TLS Certificate for HTTPS admin service.
    pub admin_cert: PathBuf,

    /// TLS Private Key for HTTPS admin service.
    pub admin_key: PathBuf,

    /// ValKey connect string.
    pub vk_uri: Option<String>,
}

impl Default for VSConfig {
    fn default() -> Self {
        VSConfig {
            core: CoreSection::default(),
        }
    }
}
impl Default for CoreSection {
    fn default() -> Self {
        CoreSection {
            vs_addr: Some(IpAddr::V6(zpr::VS_ZPR_ADDR)),
            vsapi_port: Some(zpr::VSAPI_PORT),
            admin_port: Some(zpr::ADMIN_HTTPS_PORT),
            admin_cert: PathBuf::from("admin-tls-cert.pem"),
            admin_key: PathBuf::from("admin-tls-key.pem"),
            vk_uri: Some(zpr::VALKEY_URI.to_string()),
        }
    }
}

impl VSConfig {
    /// Load configuration from a file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, VSError> {
        let contents = std::fs::read_to_string(path)?;
        let cfg: VSConfig = toml::from_str(&contents)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_override_one_field_deserialize() {
        let cfg: VSConfig = toml::from_str(
            r#"
        [core]
        vsapi_port = 9999
        "#,
        )
        .unwrap();
        assert_eq!(cfg.core.vk_uri, Some(zpr::VALKEY_URI.to_string()));
        assert_eq!(cfg.core.vsapi_port, Some(9999));
    }
}
