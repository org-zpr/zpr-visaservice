//! General database functions.

mod actor;
mod node;
mod policy;
mod visa;

pub use actor::ActorRepo;
pub use node::{Node, NodeRepo};
pub use policy::PolicyRepo;
pub use visa::{NodeVisaState, VisaRepo};

use chrono::Utc;
use percent_encoding::CONTROLS;
use percent_encoding::{AsciiSet, percent_decode_str, utf8_percent_encode};
use std::net::IpAddr;

// Encode '%' and ':' for KeyString type strings.
const KEY_ESCAPES: &AsciiSet = &CONTROLS.add(b'%').add(b':');

#[derive(Clone)]
pub struct Handle {
    pub conn: redis::aio::ConnectionManager,
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

impl Handle {
    /// Create a new database handle from a redis connection manager.
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Handle { conn }
    }
}
