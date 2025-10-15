use serde::Serialize;
use std::time::{Duration, SystemTime};

/// used to be called EPID
pub const KATTR_ZPR_ADDR: &str = "zpr.addr";

pub const KATTR_CONNECT_VIA: &str = "zpr.connect_via";

/// list of services provided.
pub const KATTR_SERVICES: &str = "zpr.services";
pub const KATTR_CN: &str = "endpoint.zpr.adapter.cn";

/// From the perspective of the evaluator, and actor is just a bunch of
/// attributes and provided services.  The provided services is stored
/// under the [KAttrServices] attribute key.
#[derive(Debug, Clone, Serialize)]
pub struct Actor {
    attrs: Vec<Attribute>,
    provider: bool,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct Attribute {
    key: String,
    value: String,
    expires_at: SystemTime,
}

impl Attribute {
    pub fn get_key(&self) -> &str {
        &self.key
    }

    pub fn get_value(&self) -> &str {
        &self.value
    }

    pub fn get_expires(&self) -> SystemTime {
        self.expires_at
    }

    // Treat value as a comma-separated list and check if it contains v.
    fn value_has(&self, v: &str) -> bool {
        self.value.split(',').any(|s| s.trim() == v)
    }

    fn value_has_all(&self, vs: &[String]) -> bool {
        for v in vs {
            if !self.value_has(v) {
                return false;
            }
        }
        true
    }

    fn value_has_any(&self, vs: &[String]) -> bool {
        for v in vs {
            if self.value_has(v) {
                return true;
            }
        }
        false
    }
}

impl Actor {
    pub fn new() -> Self {
        Actor {
            attrs: Vec::new(),
            provider: false,
        }
    }

    pub fn attrs_iter(&self) -> std::slice::Iter<'_, Attribute> {
        self.attrs.iter()
    }

    pub fn add_attr(&mut self, key: &str, value: &str, expires_in: Duration) {
        self.attrs.push(Attribute {
            key: key.to_string(),
            value: value.to_string(),
            expires_at: SystemTime::now() + expires_in,
        });
        if key == KATTR_SERVICES && !value.is_empty() {
            self.provider = true;
        }
    }

    pub fn is_provider(&self) -> bool {
        self.provider
    }

    pub fn provides(&self, service_id: &str) -> bool {
        self.attrs
            .iter()
            .any(|a| a.key == KATTR_SERVICES && a.value_has(service_id))
    }

    pub fn has_attribute_named(&self, key: &str) -> bool {
        self.attrs.iter().any(|a| a.key == key)
    }

    pub fn has_attribute_value(&self, key: &str, value: &str) -> bool {
        self.attrs.iter().any(|a| a.key == key && a.value == value)
    }

    /// TRUE if all attribute values are present.
    pub fn has_attribute_values(&self, key: &str, values: &[String]) -> bool {
        self.attrs
            .iter()
            .any(|a| a.key == key && a.value_has_all(values))
    }

    /// TRUE if any attribute value from `values` is present.
    pub fn has_any_attribute_values(&self, key: &str, values: &[String]) -> bool {
        self.attrs
            .iter()
            .any(|a| a.key == key && a.value_has_any(values))
    }
}
