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
    use crate::attribute::Attribute;
    use std::time::Duration;

    #[test]
    fn test_add_attribute_zpr_addr() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ZPR_ADDR.to_string(),
            "192.168.1.1".to_string(),
            Duration::from_secs(3600), // 1 hour
        );

        actor.add_attribute(attr).unwrap();

        assert_eq!(actor.attrs.len(), 1);
        assert_eq!(actor.get_zpr_addr(), Some(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_add_attribute_invalid_zpr_addr() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ZPR_ADDR.to_string(),
            "not-an-ip".to_string(),
            Duration::from_secs(3600), // 1 hour
        );

        match actor.add_attribute(attr) {
            Ok(_) => panic!("Expected error for invalid IP address"),
            Err(e) => assert!(
                e.to_string()
                    .contains("Invalid IP address in zpr.addr attribute")
            ),
        }
    }

    #[test]
    fn test_add_attribute_services() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::SERVICES.to_string(),
            "service1,service2".to_string(),
            Duration::from_secs(3600), // 1 hour
        );

        actor.add_attribute(attr).unwrap();

        assert_eq!(actor.attrs.len(), 1);
        assert!(actor.is_provider());
    }

    #[test]
    fn test_add_attribute_services_empty() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::SERVICES.to_string(),
            "".to_string(),
            Duration::from_secs(3600), // 1 hour
        );

        actor.add_attribute(attr).unwrap();

        assert_eq!(actor.attrs.len(), 1);
        assert!(!actor.is_provider());
    }

    #[test]
    fn test_add_attribute_cn() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::CN.to_string(),
            "test-node".to_string(),
            Duration::from_secs(3600), // 1 hour
        );

        actor.add_attribute(attr).unwrap();

        assert_eq!(actor.attrs.len(), 1);
        assert_eq!(actor.get_cn(), Some(&"test-node".to_string()));
    }

    #[test]
    fn test_add_attribute_role_adapter() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ROLE.to_string(),
            ROLE_ADAPTER.to_string(),
            Duration::from_secs(3600), // 1 hour
        );

        actor.add_attribute(attr).unwrap();

        assert_eq!(actor.attrs.len(), 1);
        assert_eq!(actor.role, Role::Adapter);
        assert!(!actor.is_node());
    }

    #[test]
    fn test_add_attribute_role_node() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ROLE.to_string(),
            ROLE_NODE.to_string(),
            Duration::from_secs(3600), // 1 hour
        );

        actor.add_attribute(attr).unwrap();

        assert_eq!(actor.attrs.len(), 1);
        assert_eq!(actor.role, Role::Node);
        assert!(actor.is_node());
    }

    #[test]
    fn test_add_attribute_role_unknown() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ROLE.to_string(),
            "unknown-role".to_string(),
            Duration::from_secs(3600), // 1 hour
        );

        match actor.add_attribute(attr) {
            Ok(_) => panic!("Expected error for unknown role"),
            Err(e) => assert!(e.to_string().contains("role must be 'node' or 'adapter'")),
        }

        assert_eq!(actor.attrs.len(), 0);
        assert_eq!(actor.role, Role::Unknown);
        assert!(!actor.is_node());
    }

    #[test]
    fn test_add_attr_from_parts() {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts(key::CN, "test-node", Duration::from_secs(60))
            .unwrap();

        assert_eq!(actor.attrs.len(), 1);
        assert_eq!(actor.get_cn(), Some(&"test-node".to_string()));
    }

    #[test]
    fn test_attrs_iter() {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts("key1", "value1", Duration::from_secs(60))
            .unwrap();
        actor
            .add_attr_from_parts("key2", "value2", Duration::from_secs(60))
            .unwrap();

        let attrs: Vec<_> = actor.attrs_iter().collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].get_key(), "key1");
        assert_eq!(attrs[0].get_value(), "value1");
        assert_eq!(attrs[1].get_key(), "key2");
        assert_eq!(attrs[1].get_value(), "value2");
    }

    #[test]
    fn test_provides_service() {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts(
                key::SERVICES,
                "service1,service2,service3",
                Duration::from_secs(60),
            )
            .unwrap();

        assert!(actor.provides("service1"));
        assert!(actor.provides("service2"));
        assert!(actor.provides("service3"));
        assert!(!actor.provides("service4"));
    }

    #[test]
    fn test_provides_service_with_spaces() {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts(
                key::SERVICES,
                "service1, service2 , service3",
                Duration::from_secs(60),
            )
            .unwrap();

        assert!(actor.provides("service1"));
        assert!(actor.provides("service2"));
        assert!(actor.provides("service3"));
        assert!(!actor.provides("service4"));
    }

    #[test]
    fn test_has_attribute_named() {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts("test.key", "test.value", Duration::from_secs(60))
            .unwrap();

        assert!(actor.has_attribute_named("test.key"));
        assert!(!actor.has_attribute_named("nonexistent.key"));
    }

    #[test]
    fn test_has_attribute_value() {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts("test.key", "test.value", Duration::from_secs(60))
            .unwrap();

        assert!(actor.has_attribute_value("test.key", "test.value"));
        assert!(!actor.has_attribute_value("test.key", "wrong.value"));
        assert!(!actor.has_attribute_value("wrong.key", "test.value"));
    }

    #[test]
    fn test_has_attribute_values_all() {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts("test.key", "value1,value2,value3", Duration::from_secs(60))
            .unwrap();

        let values = vec!["value1".to_string(), "value2".to_string()];
        assert!(actor.has_attribute_values("test.key", &values));

        let values_missing = vec!["value1".to_string(), "value4".to_string()];
        assert!(!actor.has_attribute_values("test.key", &values_missing));

        let empty_values = vec![];
        assert!(actor.has_attribute_values("test.key", &empty_values));
    }

    #[test]
    fn test_has_any_attribute_values() {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts("test.key", "value1,value2,value3", Duration::from_secs(60))
            .unwrap();

        let values_some_match = vec!["value1".to_string(), "value4".to_string()];
        assert!(actor.has_any_attribute_values("test.key", &values_some_match));

        let values_no_match = vec!["value4".to_string(), "value5".to_string()];
        assert!(!actor.has_any_attribute_values("test.key", &values_no_match));

        let empty_values = vec![];
        assert!(!actor.has_any_attribute_values("test.key", &empty_values));
    }

    #[test]
    fn test_multiple_attributes_same_key() {
        let mut actor = Actor::new();
        actor
            .add_attr_from_parts("test.key", "value1", Duration::from_secs(60))
            .unwrap();
        actor
            .add_attr_from_parts("test.key", "value2", Duration::from_secs(60))
            .unwrap();

        assert_eq!(actor.attrs.len(), 2);
        assert!(actor.has_attribute_value("test.key", "value1"));
        assert!(actor.has_attribute_value("test.key", "value2"));
    }

    #[test]
    fn test_complex_actor_setup() {
        let mut actor = Actor::new();

        // Set up a complex actor with multiple attributes
        actor
            .add_attr_from_parts(key::ZPR_ADDR, "10.0.0.1", Duration::from_secs(60))
            .unwrap();
        actor
            .add_attr_from_parts(key::CN, "my-adapter", Duration::from_secs(60))
            .unwrap();
        actor
            .add_attr_from_parts(key::ROLE, ROLE_ADAPTER, Duration::from_secs(60))
            .unwrap();
        actor
            .add_attr_from_parts(
                key::SERVICES,
                "auth,database,logging",
                Duration::from_secs(60),
            )
            .unwrap();
        actor
            .add_attr_from_parts("custom.attr", "custom.value", Duration::from_secs(60))
            .unwrap();

        // Verify all the properties
        assert_eq!(actor.attrs.len(), 5);
        assert_eq!(actor.get_zpr_addr(), Some(&"10.0.0.1".parse().unwrap()));
        assert_eq!(actor.get_cn(), Some(&"my-adapter".to_string()));
        assert_eq!(actor.role, Role::Adapter);
        assert!(!actor.is_node());
        assert!(actor.is_provider());

        // Check services
        assert!(actor.provides("auth"));
        assert!(actor.provides("database"));
        assert!(actor.provides("logging"));
        assert!(!actor.provides("unknown"));

        // Check custom attribute
        assert!(actor.has_attribute_named("custom.attr"));
        assert!(actor.has_attribute_value("custom.attr", "custom.value"));
    }

    #[test]
    fn test_ipv6_address() {
        let mut actor = Actor::new();
        let attr = Attribute::new_expiring_in(
            key::ZPR_ADDR.to_string(),
            "::1".to_string(),
            Duration::from_secs(3600), // 1 hour
        );

        actor.add_attribute(attr).unwrap();

        assert_eq!(actor.get_zpr_addr(), Some(&"::1".parse().unwrap()));
    }
}
