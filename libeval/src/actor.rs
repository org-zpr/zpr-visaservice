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
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Hash)]
pub enum Role {
    #[default]
    Unknown,
    Adapter,
    Node,
}

/// From the perspective of the evaluator, and actor is just a bunch of
/// attributes and provided services.  The provided services is stored
/// under the [Key::SERVICES] attribute key.
#[derive(Debug, Default, Clone, Serialize, Hash)]
pub struct Actor {
    // Attributes associated with this actor.
    attrs: Vec<Attribute>,

    // Once authenticated, an actor will have one or more identity attributes.
    // The names are kept here in order.
    identity_keys: Vec<String>,

    // These are all pulled from the attributes vec if/when set.
    cn: Option<String>,
    role: Role,
    provider: bool,
    zpr_addr: Option<IpAddr>,
}

impl Actor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attrs_iter(&self) -> impl Iterator<Item = &Attribute> {
        self.attrs.iter()
    }

    /// Add the name of an identity attribute. The attribute must
    /// exist or an error is returned.  The `order` parameter is the
    /// priority of the key, 0 is highest.  Passing usize::MAX appends
    /// to the end.
    pub fn add_identity_key(&mut self, order: usize, key: &str) -> Result<(), AttributeError> {
        if !self.has_attribute_named(key) {
            return Err(AttributeError::AttributeError(format!(
                "cannot add identity key '{}', attribute not present",
                key
            )));
        }
        if order >= self.identity_keys.len() {
            self.identity_keys.push(key.to_string());
        } else {
            self.identity_keys.insert(order, key.to_string());
        }
        Ok(())
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

    /// If there are identity attributes, the values are returned here
    /// in order.
    pub fn get_identity(&self) -> Option<Vec<&str>> {
        if self.identity_keys.is_empty() {
            None
        } else {
            Some(
                self.identity_keys
                    .iter()
                    .filter_map(|key| {
                        self.attrs
                            .iter()
                            .find(|a| a.get_key() == key)
                            .map(|a| a.get_value())
                    })
                    .collect(),
            )
        }
    }

    pub fn is_provider(&self) -> bool {
        self.provider
    }

    pub fn is_node(&self) -> bool {
        matches!(self.role, Role::Node)
    }

    pub fn get_cn(&self) -> Option<&str> {
        self.cn.as_deref()
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
        assert_eq!(actor.get_cn(), Some("my-test-node"));
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

    #[test]
    fn test_add_identity_key_success() {
        let mut actor = Actor::new();
        // First add an attribute that can be used as an identity
        let attr = Attribute::new_expiring_in(
            "user.email".to_string(),
            "test@example.com".to_string(),
            Duration::from_secs(3600),
        );
        actor.add_attribute(attr).unwrap();

        // Now add it as an identity key
        let result = actor.add_identity_key(0, "user.email");

        assert!(result.is_ok());
        assert_eq!(actor.identity_keys.len(), 1);
        assert_eq!(actor.identity_keys[0], "user.email");
    }

    #[test]
    fn test_add_identity_key_missing_attribute() {
        let mut actor = Actor::new();

        // Try to add an identity key for an attribute that doesn't exist
        let result = actor.add_identity_key(0, "user.email");

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("attribute not present")
        );
        assert_eq!(actor.identity_keys.len(), 0);
    }

    #[test]
    fn test_add_identity_key_at_beginning() {
        let mut actor = Actor::new();
        // Add multiple attributes
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.email".to_string(),
                "test@example.com".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.id".to_string(),
                "12345".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.name".to_string(),
                "John Doe".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();

        // Add identity keys in specific order
        actor.add_identity_key(0, "user.email").unwrap();
        actor.add_identity_key(0, "user.id").unwrap(); // Insert at beginning

        assert_eq!(actor.identity_keys.len(), 2);
        assert_eq!(actor.identity_keys[0], "user.id");
        assert_eq!(actor.identity_keys[1], "user.email");
    }

    #[test]
    fn test_add_identity_key_at_end() {
        let mut actor = Actor::new();
        // Add multiple attributes
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.email".to_string(),
                "test@example.com".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.id".to_string(),
                "12345".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();

        // Add identity keys
        actor.add_identity_key(0, "user.email").unwrap();
        actor.add_identity_key(usize::MAX, "user.id").unwrap(); // Append to end

        assert_eq!(actor.identity_keys.len(), 2);
        assert_eq!(actor.identity_keys[0], "user.email");
        assert_eq!(actor.identity_keys[1], "user.id");
    }

    #[test]
    fn test_add_identity_key_in_middle() {
        let mut actor = Actor::new();
        // Add multiple attributes
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.email".to_string(),
                "test@example.com".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.id".to_string(),
                "12345".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.name".to_string(),
                "John Doe".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();

        // Add identity keys
        actor.add_identity_key(0, "user.email").unwrap();
        actor.add_identity_key(1, "user.name").unwrap();
        actor.add_identity_key(1, "user.id").unwrap(); // Insert in middle

        assert_eq!(actor.identity_keys.len(), 3);
        assert_eq!(actor.identity_keys[0], "user.email");
        assert_eq!(actor.identity_keys[1], "user.id");
        assert_eq!(actor.identity_keys[2], "user.name");
    }

    #[test]
    fn test_get_identity_empty() {
        let actor = Actor::new();

        let identity = actor.get_identity();

        assert!(identity.is_none());
    }

    #[test]
    fn test_get_identity_single_key() {
        let mut actor = Actor::new();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.email".to_string(),
                "test@example.com".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor.add_identity_key(0, "user.email").unwrap();

        let identity = actor.get_identity();

        assert!(identity.is_some());
        let identity = identity.unwrap();
        assert_eq!(identity.len(), 1);
        assert_eq!(identity[0], "test@example.com");
    }

    #[test]
    fn test_get_identity_multiple_keys() {
        let mut actor = Actor::new();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.email".to_string(),
                "test@example.com".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.id".to_string(),
                "12345".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "user.name".to_string(),
                "John Doe".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();

        actor.add_identity_key(0, "user.email").unwrap();
        actor.add_identity_key(1, "user.id").unwrap();
        actor.add_identity_key(2, "user.name").unwrap();

        let identity = actor.get_identity();

        assert!(identity.is_some());
        let identity = identity.unwrap();
        assert_eq!(identity.len(), 3);
        assert_eq!(identity[0], "test@example.com");
        assert_eq!(identity[1], "12345");
        assert_eq!(identity[2], "John Doe");
    }

    #[test]
    fn test_get_identity_preserves_order() {
        let mut actor = Actor::new();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "attr.a".to_string(),
                "value_a".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "attr.b".to_string(),
                "value_b".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();
        actor
            .add_attribute(Attribute::new_expiring_in(
                "attr.c".to_string(),
                "value_c".to_string(),
                Duration::from_secs(3600),
            ))
            .unwrap();

        // Add in specific order: b, c, a
        actor.add_identity_key(0, "attr.b").unwrap();
        actor.add_identity_key(1, "attr.c").unwrap();
        actor.add_identity_key(2, "attr.a").unwrap();

        let identity = actor.get_identity();

        assert!(identity.is_some());
        let identity = identity.unwrap();
        assert_eq!(identity.len(), 3);
        // Should return values in the order keys were added
        assert_eq!(identity[0], "value_b");
        assert_eq!(identity[1], "value_c");
        assert_eq!(identity[2], "value_a");
    }
}
