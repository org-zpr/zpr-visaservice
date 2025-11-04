use serde::Serialize;
use std::time::{Duration, SystemTime};

pub mod key {

    /// used to be called EPID
    pub const ZPR_ADDR: &str = "zpr.addr";

    /// Dock ZPR address
    pub const CONNECT_VIA: &str = "zpr.connect_via";

    /// List of services provided.
    pub const SERVICES: &str = "zpr.services";

    /// CN value
    pub const CN: &str = "endpoint.zpr.adapter.cn";

    /// Substrate address is a SocketAddr.to_string()
    pub const SUBSTRATE_ADDR: &str = "zpr.substrate_addr";

    /// One of the ROLE_ constants.
    pub const ROLE: &str = "zpr.role";

    /// Policy install version when actor last authenticated/permitted.
    pub const VINST: &str = "zpr.vinst";
}

pub const ROLE_NODE: &str = "node";
pub const ROLE_ADAPTER: &str = "adapter";

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct Attribute {
    key: String,
    value: String,
    expires_at: SystemTime,
}

impl Attribute {
    pub fn new(key: String, value: String, expires_at: SystemTime) -> Self {
        Attribute {
            key,
            value,
            expires_at,
        }
    }

    pub fn new_expiring_in(key: String, value: String, expires_in: Duration) -> Self {
        Attribute {
            key,
            value,
            expires_at: SystemTime::now() + expires_in,
        }
    }

    /// Helper to create an attribute that functionally never expires by setting the
    /// expiration in the far future.
    pub fn new_non_expiring(key: String, value: String) -> Self {
        Attribute {
            key,
            value,
            expires_at: SystemTime::now() + Duration::from_secs(u64::MAX),
        }
    }

    pub fn get_key(&self) -> &str {
        &self.key
    }

    pub fn get_value(&self) -> &str {
        &self.value
    }

    pub fn get_expires(&self) -> SystemTime {
        self.expires_at
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    // Treat value as a comma-separated list and check if it contains v.
    pub fn value_has(&self, v: &str) -> bool {
        self.value.split(',').any(|s| s.trim() == v)
    }

    pub fn value_has_all(&self, vs: &[String]) -> bool {
        for v in vs {
            if !self.value_has(v) {
                return false;
            }
        }
        true
    }

    pub fn value_has_any(&self, vs: &[String]) -> bool {
        for v in vs {
            if self.value_has(v) {
                return true;
            }
        }
        false
    }
}
