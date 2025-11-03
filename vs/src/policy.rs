use openssl::pkey::{PKey, Public};
use std::collections::HashMap;

#[derive(Default)]
pub struct Policy {
    bootstrap_keys: HashMap<String, PKey<Public>>,
}

impl Policy {
    pub fn new_empty() -> Self {
        Policy::default()
    }

    pub fn get_bootstrap_key_by_cn(&self, cn: &str) -> Option<PKey<Public>> {
        self.bootstrap_keys.get(cn).cloned()
    }
}
