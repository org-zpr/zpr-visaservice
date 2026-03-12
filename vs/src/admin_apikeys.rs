use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::ServiceError;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Revoked,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Read,
    #[serde(rename = "readwrite")]
    ReadWrite,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiKeyRecord {
    pub owner: String,
    pub permission: Permission,
    pub status: KeyStatus,
    pub created: String,
    pub secret_hash: String,
    pub description: String,
}

#[derive(Debug)]
pub struct Permit {
    pub owner: String,
    permission: Permission,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeysFile {
    pub keys: HashMap<String, ApiKeyRecord>,
}

pub struct ReloadableApiKeys {
    keys_file_path: std::path::PathBuf,
    keys_file: RwLock<KeysFile>,
}

impl KeysFile {
    pub fn empty() -> Self {
        KeysFile {
            keys: HashMap::new(),
        }
    }
}

impl Permit {
    pub fn can_read(&self) -> bool {
        matches!(self.permission, Permission::Read | Permission::ReadWrite)
    }

    pub fn can_write(&self) -> bool {
        matches!(self.permission, Permission::ReadWrite)
    }
}

impl ReloadableApiKeys {
    /// Create a new ReloadableApiKeys by loading from the given file path.
    /// If allow_missing is true, then if the file does not exist, an empty
    /// keys file will be used instead (but it will not be created on disk
    /// until you save or add a key). If allow_missing is false, then the file
    /// must exist and be valid or an error will be returned.
    pub fn new_from_file(
        path: std::path::PathBuf,
        allow_missing: bool,
    ) -> Result<Self, ServiceError> {
        let keys_file = if path.exists() {
            match toml::from_str(&std::fs::read_to_string(&path)?) {
                Ok(kf) => kf,
                Err(e) => {
                    return Err(ServiceError::AdminKeyError(format!(
                        "failed to parse keys file: {e}"
                    )));
                }
            }
        } else if allow_missing {
            KeysFile::empty()
        } else {
            return Err(ServiceError::AdminKeyError(format!(
                "keys file not found: {}",
                path.display()
            )));
        };
        Ok(ReloadableApiKeys {
            keys_file_path: path,
            keys_file: RwLock::new(keys_file),
        })
    }

    /// Reload the keys file from disk. If errors occur, they are returned and you will end up
    /// with no keys (i.e. all API access will be denied) until the file is fixed and this
    /// is called again.
    pub fn reload(&self) -> Result<(), ServiceError> {
        match std::fs::read_to_string(&self.keys_file_path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(kf) => {
                    let mut keys_file = self.keys_file.write().unwrap();
                    *keys_file = kf;
                    Ok(())
                }
                Err(e) => Err(ServiceError::AdminKeyError(format!(
                    "failed to parse keys file: {e}"
                ))),
            },
            Err(e) => Err(ServiceError::AdminKeyError(format!(
                "failed to read keys file: {e}"
            ))),
        }
    }

    /// Lookup a key by ID. If the key is found and active it returns the [Permit].
    pub fn lookup(&self, key_id: &str) -> Option<Permit> {
        let keys_file = self.keys_file.read().unwrap();
        keys_file.keys.get(key_id).map(|record| Permit {
            owner: record.owner.clone(),
            permission: record.permission.clone(),
        })
    }

    /// Get the number of active keys in the keys file.
    pub fn size_active(&self) -> usize {
        let keys_file = self.keys_file.read().unwrap();
        keys_file
            .keys
            .values()
            .filter(|record| record.status == KeyStatus::Active)
            .count()
    }

    /// Returns TRUE if there are no ACTIVE keys in the keys file.
    pub fn is_empty(&self) -> bool {
        return self.size_active() == 0;
    }

    /// The path from which keys are loaded.
    pub fn get_path(&self) -> &std::path::Path {
        &self.keys_file_path
    }
}

impl Default for ReloadableApiKeys {
    fn default() -> Self {
        ReloadableApiKeys {
            keys_file_path: std::path::PathBuf::new(),
            keys_file: RwLock::new(KeysFile::empty()),
        }
    }
}
