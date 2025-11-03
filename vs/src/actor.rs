use std::time::{Duration, SystemTime};

// TODO: Reconcile with libeval. Possibly we want that to manage Actors and Attributes.

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Role {
    #[default]
    Unknown,
    Adapter,
    Node,
}

pub struct ExpiringValue {
    pub value: String,
    pub expiration: SystemTime,
}

impl ExpiringValue {
    /// Helper to create an "ExpiringValue" that functionally never expires by setting the
    /// expiration in the far future.
    pub fn new_non_expiring(value: String) -> Self {
        ExpiringValue {
            value,
            expiration: SystemTime::now() + Duration::from_secs(u64::MAX),
        }
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expiration
    }
}

#[derive(Debug, Default, Clone)]
pub struct Actor {
    cn: String, // Every actor has a CN
    role: Role,
}

impl Actor {
    // TODO: not implemented
    pub fn is_node(&self) -> bool {
        matches!(self.role, Role::Node)
    }

    pub fn get_cn(&self) -> &str {
        &self.cn
    }
}
