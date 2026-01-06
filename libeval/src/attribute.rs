use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

pub const ROLE_NODE: &str = "node";
pub const ROLE_ADAPTER: &str = "adapter";
const NEVER_EXPIRES: Duration = Duration::from_secs(60 * 60 * 60 * 24 * 365 * 100); // 100 years

pub mod key {

    /// used to be called EPID
    pub const ZPR_ADDR: &str = "zpr.addr";

    /// Dock ZPR address
    pub const CONNECT_VIA: &str = "zpr.connect_via";

    /// List of services provided.
    pub const SERVICES: &str = "zpr.services";

    pub const ACTOR_HASH: &str = "zpr.actor_hash";

    /// CN value
    pub const CN: &str = "endpoint.zpr.adapter.cn";

    /// AAA network in CIDR notation
    pub const AAA_NET: &str = "endpoint.zpr.node.aaa_net";

    /// Substrate address is a SocketAddr.to_string()
    pub const SUBSTRATE_ADDR: &str = "zpr.substrate_addr";

    /// One of the ROLE_ constants.
    pub const ROLE: &str = "zpr.role";

    /// Policy install version when actor last authenticated/permitted.
    pub const VINST: &str = "zpr.vinst";
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
#[allow(dead_code)]
pub struct Attribute {
    key: String,
    value: Vec<String>,
    expires_at: SystemTime,
}

impl Attribute {
    fn collect_values<I, S>(values: I) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        values
            .into_iter()
            .map(|value| value.as_ref().to_string())
            .collect()
    }

    pub fn new<I, S>(key: String, values: I, expires_at: SystemTime) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Attribute {
            key,
            value: Self::collect_values(values),
            expires_at,
        }
    }

    /// Helper for a common case of a single value attribute.
    pub fn new_single_value(key: String, value: String, expires_at: SystemTime) -> Self {
        Attribute::new(key, std::iter::once(value), expires_at)
    }

    pub fn new_single_value_expiring_in(key: String, value: String, expires_in: Duration) -> Self {
        Attribute::new_expiring_in(key, std::iter::once(value), expires_in)
    }

    pub fn new_expiring_in<I, S>(key: String, values: I, expires_in: Duration) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Attribute::new(key, values, SystemTime::now() + expires_in)
    }

    /// Helper to create an attribute that functionally never expires by setting the
    /// expiration in the far future.
    pub fn new_single_value_non_expiring(key: String, value: String) -> Self {
        Attribute::new_non_expiring(key, std::iter::once(value))
    }

    pub fn new_non_expiring<I, S>(key: String, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Attribute::new(key, values, SystemTime::now() + NEVER_EXPIRES)
    }

    pub fn get_key(&self) -> &str {
        &self.key
    }

    pub fn get_value(&self) -> &[String] {
        &self.value
    }

    pub fn get_value_len(&self) -> usize {
        self.value.len()
    }

    pub fn get_expires(&self) -> SystemTime {
        self.expires_at
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    pub fn value_has(&self, v: &str) -> bool {
        self.value.iter().any(|s| s == v)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_has_all_true() {
        let attr = Attribute::new_non_expiring("key".to_string(), vec!["alpha", "beta", "gamma"]);
        let values = vec!["alpha".to_string(), "gamma".to_string()];

        assert!(attr.value_has_all(&values));
    }

    #[test]
    fn test_value_has_all_false() {
        let attr = Attribute::new_non_expiring("key".to_string(), vec!["alpha", "beta", "gamma"]);
        let values = vec!["alpha".to_string(), "delta".to_string()];

        assert!(!attr.value_has_all(&values));
    }

    #[test]
    fn test_value_has_any_true() {
        let attr = Attribute::new_non_expiring("key".to_string(), vec!["alpha", "beta", "gamma"]);
        let values = vec!["delta".to_string(), "beta".to_string()];

        assert!(attr.value_has_any(&values));
    }

    #[test]
    fn test_value_has_any_false() {
        let attr = Attribute::new_non_expiring("key".to_string(), vec!["alpha", "beta", "gamma"]);
        let values = vec!["delta".to_string(), "epsilon".to_string()];

        assert!(!attr.value_has_any(&values));
    }
}
