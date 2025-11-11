//! ZPR and VS constants.

use std::net::Ipv6Addr;

// We only load policy files built by this version or later.
pub const POLICY_MIN_COMPILER_MAJOR: u32 = 0;
pub const POLICY_MIN_COMPILER_MINOR: u32 = 9;
pub const POLICY_MIN_COMPILER_PATCH: u32 = 1;

/// Default VSAPI port - must be in sync with compiler since it adds policy for that.
pub const VSAPI_PORT: u16 = 5002;

/// Default VS admin HTTPS port - must be in sync with compiler since it adds policy for that.
pub const ADMIN_HTTPS_PORT: u16 = 8182;

pub const VALKEY_URI: &str = "redis://127.0.0.1:6379";

/// Default VS ZPR address - must be in sync with compiler.
pub const VS_ZPR_ADDR: Ipv6Addr = Ipv6Addr::new(
    0xfd5a, 0x5052, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, // fd5a:5052::1
);

/// Maximum allowed clock skew allowed during node authentication, in seconds.
pub const MAX_CLOCK_SKEW_SECS: u64 = 180;
