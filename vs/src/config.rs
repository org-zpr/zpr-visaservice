//! Structs that map to the TOML configuration file for the visa service.

use std::net::{IpAddr, Ipv6Addr};

use serde::Deserialize;

use crate::error::VSError;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct VSConfig {
    pub core: CoreSection,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct CoreSection {
    /// The visa service bind address - this is a constant baked into entire ZPR system.
    pub vs_addr: Option<IpAddr>,

    /// VSAPI port used by nodes to talk to the visa service VSS API.
    /// Must be kept in sync with the compiler.
    pub vsapi_port: Option<u16>,

    /// HTTPS Admin port used to control the visa service.
    /// Must be kept in sync with the compiler.
    pub admin_port: Option<u16>,

    /// Hostname or IP address for ValKey.
    pub vk_host: Option<String>,

    /// Port number for ValKey.
    pub vk_port: Option<u16>,
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
            vs_addr: Some(IpAddr::V6(Ipv6Addr::new(
                0xfd5a, 0x5052, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, // fd5a:5052::1
            ))),
            vsapi_port: Some(5002),
            admin_port: Some(8182),
            vk_host: Some("::1".to_string()),
            vk_port: Some(6379),
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
        vk_port = 9999
        "#,
        )
        .unwrap();
        assert_eq!(cfg.core.vk_host, Some("::1".to_string()));
        assert_eq!(cfg.core.vk_port, Some(9999));
    }
}
