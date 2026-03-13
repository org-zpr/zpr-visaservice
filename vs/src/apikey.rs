//! API key creation and parsing for the VS API.
//!
//! Keys have the form `zpr_vsapi.<ID>.<SECRET>` where:
//! - `ID` is an 8-character lowercase hex encoding of a 32-bit key ID.
//! - `SECRET` is the base64url-encoded (no padding) 32-byte secret value.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::hash::{Hasher, MessageDigest};

use crate::error::CryptoError;

const KEY_PREFIX: &str = "zpr_vsapi";
const SECRET_LEN: usize = 32;

#[derive(Debug)]
pub struct ApiKey {
    key_id: u32,
    secret_bytes: [u8; SECRET_LEN],
}

impl ApiKey {
    /// Create an `ApiKey` from a numeric key ID and raw secret bytes.
    #[allow(dead_code)]
    pub fn new(key_id: u32, secret_bytes: [u8; SECRET_LEN]) -> Self {
        ApiKey {
            key_id,
            secret_bytes,
        }
    }

    /// Create an `ApiKey` with a randomly generated secret for a given key ID.
    #[allow(dead_code)]
    pub fn new_generate(key_id: u32) -> Result<Self, CryptoError> {
        let mut secret_bytes = [0u8; SECRET_LEN];
        openssl::rand::rand_bytes(&mut secret_bytes)?;
        Ok(ApiKey::new(key_id, secret_bytes))
    }

    /// Parse an API key string of the form `zpr_vsapi.<id_hex>.<b64url_secret>`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.splitn(3, '.').collect();
        if parts.len() != 3 || parts[0] != KEY_PREFIX {
            return Err(format!(
                "invalid key format: expected {KEY_PREFIX}.<id>.<secret>"
            ));
        }
        let key_id = u32::from_str_radix(parts[1], 16)
            .map_err(|e| format!("invalid key id '{}': {e}", parts[1]))?;
        let decoded = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| format!("invalid secret encoding: {e}"))?;
        let secret_bytes: [u8; SECRET_LEN] = decoded
            .try_into()
            .map_err(|_| format!("invalid secret length: expected {SECRET_LEN} bytes"))?;
        Ok(ApiKey {
            key_id,
            secret_bytes,
        })
    }

    /// Return the raw secret bytes.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret_bytes
    }

    /// Return the key ID as an 8-character lowercase hex string.
    pub fn key_id_hex(&self) -> String {
        format!("{:08x}", self.key_id)
    }

    /// Return the secret as a base64url-encoded string (no padding).
    #[allow(dead_code)]
    pub fn secret_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.secret_bytes)
    }

    /// Return the full key string: `zpr_vsapi.<id_hex>.<b64url_secret>`.
    #[allow(dead_code)]
    pub fn to_key_string(&self) -> String {
        format!("{}.{}.{}", KEY_PREFIX, self.key_id_hex(), self.secret_b64())
    }

    /// Compute and return the SHA-256 hash of the secret bytes as a lowercase hex string.
    #[allow(dead_code)]
    pub fn secret_hash(&self) -> Result<String, CryptoError> {
        sha256_hex(&self.secret_bytes)
    }
}

/// Compute the SHA-256 digest of `data` and return it as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> Result<String, CryptoError> {
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    hasher.update(data)?;
    let digest = hasher.finish()?;
    Ok(hex::encode(&*digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_create_and_parse() {
        let key_id: u32 = 0x8c7f3a12;
        let secret_bytes = [0xab_u8; 32];

        let key = ApiKey::new(key_id, secret_bytes);
        let key_string = key.to_key_string();

        assert!(
            key_string.starts_with("zpr_vsapi.8c7f3a12."),
            "unexpected prefix: {key_string}"
        );

        let parsed = ApiKey::parse(&key_string).expect("parse failed");
        assert_eq!(parsed.key_id, key_id);
        assert_eq!(parsed.secret_bytes, secret_bytes);
        assert_eq!(parsed.key_id_hex(), key.key_id_hex());
        assert_eq!(parsed.secret_b64(), key.secret_b64());
    }

    #[test]
    fn hash_is_stable() {
        // SHA-256 of 32 zero bytes, verified externally.
        let secret_bytes = [0u8; 32];
        let key = ApiKey::new(0x00000001, secret_bytes);
        let hash = key.secret_hash().expect("hash failed");
        assert_eq!(
            hash,
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
    }

    #[test]
    fn hash_matches_after_parse() {
        let secret_bytes: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let key = ApiKey::new(0xdeadbeef, secret_bytes);
        let key_string = key.to_key_string();
        let hash_before = key.secret_hash().expect("hash failed");

        let parsed = ApiKey::parse(&key_string).expect("parse failed");
        let hash_after = parsed.secret_hash().expect("hash failed");

        assert_eq!(hash_before, hash_after);
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        let err = ApiKey::parse("bad_vsapi.00000001.aaaa").unwrap_err();
        assert!(err.contains("invalid key format"), "{err}");
    }

    #[test]
    fn parse_rejects_bad_id() {
        let err = ApiKey::parse("zpr_vsapi.xyz.aaaa").unwrap_err();
        assert!(err.contains("invalid key id"), "{err}");
    }

    #[test]
    fn parse_rejects_wrong_secret_length() {
        // base64url of fewer than 32 bytes
        let short = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let err = ApiKey::parse(&format!("zpr_vsapi.00000001.{short}")).unwrap_err();
        assert!(err.contains("invalid secret length"), "{err}");
    }
}
