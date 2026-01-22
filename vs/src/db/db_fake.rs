//! Fake database backend for testing.

use dashmap::{DashMap, DashSet};
use regex::Regex;
use std::collections::{HashMap, HashSet};
//use std::sync::RwLock;
use std::time::Instant;
use tokio::sync::RwLock;

use crate::db::{DbConnection, DbOp, DbResult};

pub struct FakeDb {
    store: DashMap<String, Entry>,

    // All the operations take read lock except *_atomic ones which take write lock.
    lock: RwLock<()>,
}

struct Entry {
    value: FakeDbValue,
    exp: Instant,
}

enum FakeDbValue {
    Str(String),
    Bin(Vec<u8>),
    Hash(DashMap<String, String>),
    Set(DashSet<String>),
}

impl FakeDb {
    pub fn new() -> Self {
        FakeDb {
            store: DashMap::new(),
            lock: RwLock::new(()),
        }
    }
}

impl Entry {
    fn new(value: FakeDbValue) -> Self {
        Entry {
            value,
            exp: Instant::now() + std::time::Duration::from_secs(86400), // + 1 day
        }
    }

    fn new_ex(value: FakeDbValue, seconds: u64) -> Self {
        Entry {
            value,
            exp: Instant::now() + std::time::Duration::from_secs(seconds),
        }
    }
}

impl FakeDb {
    /// Remove a member from a set.
    async fn srem(&self, key: &str, member: &str) -> DbResult<()> {
        let _ = self.lock.read().await;
        if !self.exists(key).await? {
            return Ok(());
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Set(s) => {
                    s.remove(member);
                    Ok(())
                }
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "value is not a set",
                ))),
            }
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl DbConnection for FakeDb {
    /// True if the key exists (and not expired).  As a side effect this removes the
    /// key if it is expired before returning false.
    async fn exists(&self, key: &str) -> DbResult<bool> {
        let _rlock = self.lock.read().await;
        if let Some(entry) = self.store.get(key) {
            if Instant::now() > entry.exp {
                self.store.remove(key);
                return Ok(false);
            }
        }
        Ok(self.store.contains_key(key))
    }

    /// Set a string value.
    async fn set(&self, key: &str, value: &str) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        self.store.insert(
            key.to_string(),
            Entry::new(FakeDbValue::Str(value.to_string())),
        );
        Ok(())
    }

    async fn get(&self, key: &str) -> DbResult<Option<String>> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Ok(None);
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Str(s) => Ok(Some(s.clone())),
                FakeDbValue::Bin(b) => Ok(Some(String::from_utf8_lossy(b).to_string())),
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "value is not string",
                ))),
            }
        } else {
            Ok(None)
        }
    }

    /// Set a binary value.
    async fn set_bin(&self, key: &str, value: &[u8]) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        self.store.insert(
            key.to_string(),
            Entry::new(FakeDbValue::Bin(value.to_vec())),
        );
        Ok(())
    }

    /// Set a binary value with expiration.
    async fn set_bin_ex(&self, key: &str, value: &[u8], seconds: u64) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        self.store.insert(
            key.to_string(),
            Entry::new_ex(FakeDbValue::Bin(value.to_vec()), seconds),
        );
        Ok(())
    }

    /// Get a binary value.
    /// TODO: What does rust redis return when key is not found?
    async fn get_bin(&self, key: &str) -> DbResult<Vec<u8>> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "key not found",
            )));
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Bin(b) => Ok(b.clone()),
                FakeDbValue::Str(s) => Ok(s.as_bytes().to_vec()),
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "value is not binary",
                ))),
            }
        } else {
            Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "key not found",
            )))
        }
    }

    /// Delete a key.
    async fn del(&self, key: &str) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        self.store.remove(key);
        Ok(())
    }

    /// Get all members of a set.  Returns empty set if key does not exist.
    async fn smembers(&self, key: &str) -> DbResult<HashSet<String>> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Ok(HashSet::new());
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Set(s) => {
                    let mut result = HashSet::new();
                    for item in s.iter() {
                        result.insert(item.key().clone());
                    }
                    Ok(result)
                }
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "value is not a set",
                ))),
            }
        } else {
            Ok(HashSet::new())
        }
    }

    /// Get a field from a hash.
    async fn hget(&self, key: &str, field: &str) -> DbResult<Option<String>> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Ok(None);
        }
        if let Some(entry) = self.store.get(key) {
            match &entry.value {
                FakeDbValue::Hash(h) => Ok(h.get(field).map(|v| v.value().clone())),
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "value is not a hash",
                ))),
            }
        } else {
            Ok(None)
        }
    }

    /// Get all fields and values from a hash. Returns empty map if key does not exist.
    async fn hgetall(&self, key: String) -> DbResult<HashMap<String, String>> {
        let _rlock = self.lock.read().await;
        if !self.exists(&key).await? {
            return Ok(HashMap::new());
        }
        if let Some(entry) = self.store.get(&key) {
            match &entry.value {
                FakeDbValue::Hash(h) => {
                    let mut result = HashMap::new();
                    for item in h.iter() {
                        result.insert(item.key().clone(), item.value().clone());
                    }
                    Ok(result)
                }
                _ => Err(redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "value is not a hash",
                ))),
            }
        } else {
            Ok(HashMap::new())
        }
    }

    /// Set a field in a hash.
    async fn hset(&self, key: &str, field: &str, value: &str) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        let entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Hash(DashMap::new())));
        match &entry.value {
            FakeDbValue::Hash(h) => {
                h.insert(field.to_string(), value.to_string());
                Ok(())
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "value is not a hash",
            ))),
        }
    }

    /// Set the hash field only if the field with that name does not already exist.
    async fn hset_nx(&self, key: &str, field: &str, value: &str) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        let entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Hash(DashMap::new())));
        match &entry.value {
            FakeDbValue::Hash(h) => {
                h.entry(field.to_string())
                    .or_insert_with(|| value.to_string());
                Ok(())
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "value is not a hash",
            ))),
        }
    }

    /// Set multiple hash fields at once.
    async fn hset_multiple(&self, key: &str, field_values: &[(&str, &str)]) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        let entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Hash(DashMap::new())));
        match &entry.value {
            FakeDbValue::Hash(h) => {
                for (field, value) in field_values {
                    h.insert(field.to_string(), value.to_string());
                }
                Ok(())
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "value is not a hash",
            ))),
        }
    }

    /// Add a member to a set, creating the set if it does not exist.
    async fn sadd(&self, key: &str, member: &str) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        let entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Set(DashSet::new())));
        match &entry.value {
            FakeDbValue::Set(s) => {
                s.insert(member.to_string());
                Ok(())
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "value is not a set",
            ))),
        }
    }

    /// Increment number stored at key by `by` amount. If key does not exist, it is set to 0 before incrementing.
    async fn incr(&self, key: &str, by: u64) -> DbResult<u64> {
        let _rlock = self.lock.read().await;
        let mut entry = self
            .store
            .entry(key.to_string())
            .or_insert_with(|| Entry::new(FakeDbValue::Str("0".to_string())));
        match &entry.value {
            FakeDbValue::Str(s) => {
                let mut num: u64 = s.parse().map_err(|_| {
                    redis::RedisError::from((
                        redis::ErrorKind::TypeError,
                        "value is not an integer",
                    ))
                })?;
                num += by;
                entry.value = FakeDbValue::Str(num.to_string());
                Ok(num)
            }
            _ => Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "value is not a string",
            ))),
        }
    }

    /// Set key expiration in seconds.
    async fn expire(&self, key: &str, seconds: i64) -> DbResult<()> {
        let _rlock = self.lock.read().await;
        if !self.exists(key).await? {
            return Ok(());
        }
        if seconds <= 0 {
            self.store.remove(key);
            return Ok(());
        }
        if let Some(mut entry) = self.store.get_mut(key) {
            entry.exp = Instant::now() + std::time::Duration::from_secs(seconds as u64);
        }
        Ok(())
    }

    /// To simulate atomic we take a lock that prevents all the other operations
    /// from running.
    async fn atomic_pipeline(&self, ops: &[DbOp]) -> DbResult<()> {
        let _wlock = self.lock.write().await;
        for op in ops {
            match op {
                DbOp::Del(key) => {
                    self.del(key).await?;
                }
                DbOp::SRem { set_key, member } => {
                    self.srem(set_key, member).await?;
                }
                DbOp::HSet {
                    hash_key,
                    field,
                    value,
                } => {
                    self.hset(hash_key, field, value).await?;
                }
            }
        }

        Ok(())
    }

    /// Return the set of keys that match the pattern.
    async fn scan_match_all(&self, pattern: String) -> DbResult<Vec<String>> {
        let _rlock = self.lock.read().await;
        let mut results = Vec::new();
        let pattern = pattern.replace("*", ".*");
        let re = Regex::new(&pattern).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "invalid pattern regex",
                e.to_string(),
            ))
        })?;
        for key in self.store.iter().map(|e| e.key().clone()) {
            if re.is_match(&key) {
                results.push(key);
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_fake_db_set_get() {
        let db = FakeDb::new();
        db.set("key1", "value1").await.unwrap();
        let val = db.get("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));
    }
}
