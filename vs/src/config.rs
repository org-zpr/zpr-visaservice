//! Structs that map to the TOML configuration file for the visa service.

use serde::Deserialize;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use crate::error::VSError;

pub const VS_CN: &str = "vs.zpr";

pub const MAX_VISA_REQUEST_WORKERS: usize = 1024;
pub const VISA_REQUEST_QUEUE_DEPTH: usize = 1024;

// We only load policy files built by this version or later.
pub const POLICY_MIN_COMPILER_MAJOR: u32 = 0;
pub const POLICY_MIN_COMPILER_MINOR: u32 = 9;
pub const POLICY_MIN_COMPILER_PATCH: u32 = 1;

/// Default VSAPI port - must be in sync with compiler since it adds policy for that.
pub const VSAPI_PORT: u16 = 5002;

/// Default VS admin HTTPS port - must be in sync with compiler since it adds policy for that.
pub const ADMIN_HTTPS_PORT: u16 = 8182;

pub const VALKEY_URI: &str = "redis://127.0.0.1:6379";

/// Default VS ZPR address - must be in sync with compiler.
pub const VS_ZPR_ADDR: Ipv6Addr = Ipv6Addr::new(
    0xfd5a, 0x5052, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, // fd5a:5052::1
);

/// Maximum allowed clock skew allowed during node authentication, in seconds.
pub const MAX_CLOCK_SKEW_SECS: u64 = 180;

pub const DEFAULT_VISA_EXPIRATION: Duration = Duration::from_secs(4 * 60 * 60); // 4 hours

pub const DEFAULT_AUTH_EXPIRATION: Duration = Duration::from_secs(4 * 60 * 60); // 4 hours

/// How long to wait after getting the VSS addr from the node and opening a connection back to it.
/// This delay allows time for the node to install the visa before we try to use it.
pub const VSS_START_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

/// VSS worker pings the node VSS API at this interval.
pub const VSS_PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// In cases where we create visas ourselves or if no timeout is specified, use this default.
pub const DEFAULT_VISA_REQ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct VSConfig {
    pub core: CoreSection,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct CoreSection {
    /// The visa service bind address - this is a constant baked into entire ZPR system only override for testing.
    pub vs_addr: Option<IpAddr>,

    /// VSAPI port used by nodes to talk to the visa service VS API.
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
            vs_addr: Some(IpAddr::V6(VS_ZPR_ADDR)),
            vsapi_port: Some(VSAPI_PORT),
            admin_port: Some(ADMIN_HTTPS_PORT),
            admin_cert: PathBuf::from("admin-tls-cert.pem"),
            admin_key: PathBuf::from("admin-tls-key.pem"),
            vk_uri: Some(VALKEY_URI.to_string()),
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

    pub fn get_vs_addr(&self) -> IpAddr {
        self.core.vs_addr.unwrap_or(IpAddr::V6(VS_ZPR_ADDR))
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
        assert_eq!(cfg.core.vk_uri, Some(VALKEY_URI.to_string()));
        assert_eq!(cfg.core.vsapi_port, Some(9999));
    }
}
