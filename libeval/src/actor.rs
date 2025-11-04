use serde::Serialize;
use std::time::Duration;

use crate::attribute::key;
use crate::attribute::{Attribute, ROLE_ADAPTER, ROLE_NODE};

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
    cn: Option<String>,
    role: Role,
    attrs: Vec<Attribute>,
    provider: bool,
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

    pub fn add_attr_from_parts(&mut self, key: &str, value: &str, expires_in: Duration) {
        self.add_attribute(Attribute::new_expiring_in(
            key.into(),
            value.into(),
            expires_in,
        ));
    }

    pub fn add_attribute(&mut self, attr: Attribute) {
        let key = attr.get_key();
        let value = attr.get_value();
        match key {
            key::SERVICES => self.provider = !value.is_empty(),
            key::CN => self.cn = Some(value.to_string()),
            key::ROLE => match value {
                ROLE_ADAPTER => self.role = Role::Adapter,
                ROLE_NODE => self.role = Role::Node,
                _ => self.role = Role::Unknown,
            },
            _ => (),
        }
        self.attrs.push(attr);
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
