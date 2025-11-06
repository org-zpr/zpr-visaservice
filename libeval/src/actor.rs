use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;

use crate::attribute::key;
use crate::attribute::{Attribute, ROLE_ADAPTER, ROLE_NODE};

#[derive(Debug, Error)]
pub enum AttributeError {
    #[error("attribute error: {0}")]
    AttributeError(String),
}

/// Role of the actor. Can be Adapter, Node. As a default
/// the actor starts as UNKNOWN.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub enum Role {
    #[default]
    Unknown,
    Adapter,
    Node,
}

/// From the perspective of the evaluator, and actor is just a bunch of
/// attributes and provided services.  The provided services is stored
/// under the [Key::SERVICES] attribute key.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Actor {
    // Attributes associated with this actor.
    attrs: Vec<Attribute>,

    // These are all pulled from the attributes vec if/when set.
    cn: Option<String>,
    role: Role,
    provider: bool,
    zpr_addr: Option<IpAddr>,
}

impl Actor {
    pub fn new() -> Self {
        Actor {
            ..Default::default()
        }
    }

    pub fn attrs_iter(&self) -> std::slice::Iter<'_, Attribute> {
        self.attrs.iter()
    }

    /// Adds or replaces the attribute with name `key`.
    pub fn add_attr_from_parts(
        &mut self,
        key: &str,
        value: &str,
        expires_in: Duration,
    ) -> Result<(), AttributeError> {
        self.add_attribute(Attribute::new_expiring_in(
            key.into(),
            value.into(),
            expires_in,
        ))
    }

    /// Adds or replaces the attribute on the actor.
    pub fn add_attribute(&mut self, attr: Attribute) -> Result<(), AttributeError> {
        let key = attr.get_key();
        let value = attr.get_value();
        match key {
            key::ZPR_ADDR => {
                if let Ok(ip) = value.parse::<IpAddr>() {
                    self.zpr_addr = Some(ip);
                } else {
                    return Err(AttributeError::AttributeError(format!(
                        "Invalid IP address in zpr.addr attribute: '{}'",
                        value
                    )));
                }
            }
            key::SERVICES => self.provider = !value.is_empty(),
            key::CN => self.cn = Some(value.to_string()),
            key::ROLE => match value {
                ROLE_ADAPTER => self.role = Role::Adapter,
                ROLE_NODE => self.role = Role::Node,
                _ => {
                    return Err(AttributeError::AttributeError(format!(
                        "role must be 'node' or 'adapter', not: '{}'",
                        value
                    )));
                }
            },
            _ => (),
        }
        self.attrs.push(attr);
        Ok(())
    }

    pub fn is_provider(&self) -> bool {
        self.provider
    }

    pub fn is_node(&self) -> bool {
        matches!(self.role, Role::Node)
    }

    pub fn get_cn(&self) -> Option<&String> {
        self.cn.as_ref()
    }

    pub fn get_zpr_addr(&self) -> Option<&IpAddr> {
        self.zpr_addr.as_ref()
    }

    pub fn provides(&self, service_id: &str) -> bool {
        self.attrs
            .iter()
            .any(|a| a.get_key() == key::SERVICES && a.value_has(service_id))
    }

    pub fn has_attribute_named(&self, key: &str) -> bool {
        self.attrs.iter().any(|a| a.get_key() == key)
    }

    pub fn has_attribute_value(&self, key: &str, value: &str) -> bool {
        self.attrs
            .iter()
            .any(|a| a.get_key() == key && a.get_value() == value)
    }

    /// TRUE if all attribute values are present.
    pub fn has_attribute_values(&self, key: &str, values: &[String]) -> bool {
        self.attrs
            .iter()
            .any(|a| a.get_key() == key && a.value_has_all(values))
    }

    /// TRUE if any attribute value from `values` is present.
    pub fn has_any_attribute_values(&self, key: &str, values: &[String]) -> bool {
        self.attrs
            .iter()
            .any(|a| a.get_key() == key && a.value_has_any(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_add_attribute_zpr_addr_ipv4() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ZPR_ADDR.to_string(),
            "192.168.1.100".to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(
            actor.get_zpr_addr(),
            Some(&"192.168.1.100".parse().unwrap())
        );
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_zpr_addr_ipv6() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ZPR_ADDR.to_string(),
            "::1".to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(actor.get_zpr_addr(), Some(&"::1".parse().unwrap()));
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_zpr_addr_invalid() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ZPR_ADDR.to_string(),
            "not-an-ip-address".to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid IP address")
        );
        assert_eq!(actor.get_zpr_addr(), None); // Should remain None
        assert_eq!(actor.attrs.len(), 0); // Attribute should not be added on error
    }

    #[test]
    fn test_add_attribute_services_non_empty() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::SERVICES.to_string(),
            "auth,database,logging".to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert!(actor.is_provider());
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_services_empty() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::SERVICES.to_string(),
            "".to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert!(!actor.is_provider());
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_cn() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::CN.to_string(),
            "my-test-node".to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(actor.get_cn(), Some(&"my-test-node".to_string()));
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_role_adapter() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ROLE.to_string(),
            ROLE_ADAPTER.to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(actor.role, Role::Adapter);
        assert!(!actor.is_node());
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_role_node() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ROLE.to_string(),
            ROLE_NODE.to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        assert_eq!(actor.role, Role::Node);
        assert!(actor.is_node());
        assert_eq!(actor.attrs.len(), 1);
    }

    #[test]
    fn test_add_attribute_role_invalid() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ROLE.to_string(),
            "invalid-role".to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("role must be"));
        assert_eq!(actor.role, Role::Unknown); // Should remain unchanged
        assert_eq!(actor.attrs.len(), 0); // Attribute should not be added on error
    }

    #[test]
    fn test_add_attribute_non_special_key() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            "custom.attribute".to_string(),
            "custom-value".to_string(),
            Duration::from_secs(3600),
        );

        let result = actor.add_attribute(attr);

        assert!(result.is_ok());
        // All internal fields should remain at their defaults
        assert_eq!(actor.get_zpr_addr(), None);
        assert!(!actor.is_provider());
        assert_eq!(actor.get_cn(), None);
        assert_eq!(actor.role, Role::Unknown);
        // But the attribute should be added to the list
        assert_eq!(actor.attrs.len(), 1);
        assert!(actor.has_attribute_named("custom.attribute"));
        assert!(actor.has_attribute_value("custom.attribute", "custom-value"));
    }

    #[test]
    fn test_add_attribute_overwrites_internal_fields() {
        let mut actor = Actor::new();

        // Set initial values
        let initial_attr = Attribute::new_expiring_in(
            key::ROLE.to_string(),
            ROLE_ADAPTER.to_string(),
            Duration::from_secs(3600),
        );
        assert!(actor.add_attribute(initial_attr).is_ok());
        assert_eq!(actor.role, Role::Adapter);

        // Overwrite with new value
        let new_attr = Attribute::new_expiring_in(
            key::ROLE.to_string(),
            ROLE_NODE.to_string(),
            Duration::from_secs(3600),
        );
        assert!(actor.add_attribute(new_attr).is_ok());

        // Should have the new value
        assert_eq!(actor.role, Role::Node);
        assert!(actor.is_node());
        assert_eq!(actor.attrs.len(), 2); // Both attributes are kept in the list
    }
}
