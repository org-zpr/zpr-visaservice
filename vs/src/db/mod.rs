//! General database functions.

mod actor;
mod db_fake;
mod db_redis;
mod node;
mod policy;
mod visa;

pub use actor::{ActorRepo, Role};
pub use db_redis::RedisDb;
pub use node::{Node, NodeRepo};
pub use policy::PolicyRepo;
pub use visa::{NodeVisaState, VisaRepo};

#[cfg(test)]
pub use db_fake::FakeDb;

use chrono::Utc;
use percent_encoding::CONTROLS;
use percent_encoding::{AsciiSet, percent_decode_str, utf8_percent_encode};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

// Encode '%' and ':' for KeyString type strings.
const KEY_ESCAPES: &AsciiSet = &CONTROLS.add(b'%').add(b':');

pub type DbResult<T> = redis::RedisResult<T>;

#[async_trait::async_trait]
pub trait DbConnection: Send + Sync {
    async fn exists(&self, key: &str) -> DbResult<bool>;
    async fn set(&self, key: &str, value: &str) -> DbResult<()>;

    #[allow(dead_code)]
    async fn get(&self, key: &str) -> DbResult<Option<String>>;

    async fn set_bin(&self, key: &str, value: &[u8]) -> DbResult<()>;
    async fn set_bin_ex(&self, key: &str, value: &[u8], seconds: u64) -> DbResult<()>;
    async fn get_bin(&self, key: &str) -> DbResult<Vec<u8>>;
    async fn del(&self, key: &str) -> DbResult<()>;
    async fn smembers(&self, key: &str) -> DbResult<HashSet<String>>;
    async fn hget(&self, key: &str, field: &str) -> DbResult<Option<String>>;
    async fn hgetall(&self, key: String) -> DbResult<HashMap<String, String>>;
    async fn hset(&self, key: &str, field: &str, value: &str) -> DbResult<()>;
    async fn hset_nx(&self, key: &str, field: &str, value: &str) -> DbResult<()>;
    async fn hset_multiple(&self, key: &str, field_values: &[(&str, &str)]) -> DbResult<()>;
    async fn sadd(&self, key: &str, member: &str) -> DbResult<()>;
    async fn incr(&self, key: &str, by: u64) -> DbResult<u64>;
    async fn expire(&self, key: &str, seconds: i64) -> DbResult<()>;

    async fn atomic_pipeline(&self, ops: &[DbOp]) -> DbResult<()>;

    async fn scan_match_all(&self, pattern: String) -> DbResult<Vec<String>>;
}

pub enum DbOp {
    Del(String),
    SRem {
        set_key: String,
        member: String,
    },
    HSet {
        hash_key: String,
        field: String,
        value: String,
    },
}

/// In the redis, we sometimes need to use a ZPR address as part of a key.
/// In that case we use this `ZAddr` type instead.  Only thing it it does
/// is replace colons in IPv6 addresses with dashes.
pub struct ZAddr(pub String);

/// In redis if we want to use user supllied text as part of a key we
/// want to remove any colons in there so we use percent encoding.
/// All colons and '%' in the original are encoded.
pub struct KeyString(pub String);

impl From<&str> for KeyString {
    fn from(s: &str) -> Self {
        let encoded = utf8_percent_encode(s, KEY_ESCAPES).to_string();
        KeyString(encoded)
    }
}

impl TryFrom<KeyString> for String {
    type Error = std::str::Utf8Error;
    fn try_from(ks: KeyString) -> Result<Self, Self::Error> {
        let decoded = percent_decode_str(&ks.0)
            .decode_utf8()
            .map(|cow| cow.into_owned())?;
        Ok(decoded)
    }
}

impl KeyString {
    /// Create a KeyString from a raw (already encoded) string.
    /// Caller must ensure that the string is properly encoded.
    pub fn from_raw(s: String) -> Self {
        KeyString(s)
    }
}

impl From<IpAddr> for ZAddr {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a4) => ZAddr(a4.to_string()),
            IpAddr::V6(a6) => {
                let ipv6str = a6.to_string();
                ZAddr(ipv6str.replace(":", "-"))
            }
        }
    }
}

impl From<&IpAddr> for ZAddr {
    fn from(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(a4) => ZAddr(a4.to_string()),
            IpAddr::V6(a6) => {
                let ipv6str = a6.to_string();
                ZAddr(ipv6str.replace(":", "-"))
            }
        }
    }
}

impl TryFrom<ZAddr> for IpAddr {
    type Error = std::net::AddrParseError;
    fn try_from(zaddr: ZAddr) -> Result<Self, Self::Error> {
        if zaddr.0.contains('-') {
            // IPv6
            let ipv6str = zaddr.0.replace("-", ":");
            Ok(IpAddr::V6(ipv6str.parse()?))
        } else {
            // IPv4
            Ok(IpAddr::V4(zaddr.0.parse()?))
        }
    }
}

impl std::fmt::Display for ZAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for KeyString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ZAddr {
    /// If you already have a "zaddr" encoded string, use this to create a ZAddr.
    pub fn new_from_encoded(s: &str) -> Self {
        ZAddr(s.into())
    }

    /// Get the string representation of this ZAddr.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl KeyString {
    /// Get the string representation of this KeyString.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn to_string(&self) -> String {
        self.0.clone()
    }
}

/// All database string timestamps look like this.
pub fn gen_timestamp() -> String {
    let now = Utc::now();
    now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
