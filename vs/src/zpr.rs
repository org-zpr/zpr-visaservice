//! ZPR and related constants.

use std::net::Ipv6Addr;

pub const VSAPI_PORT: u16 = 5002;

pub const ADMIN_HTTPS_PORT: u16 = 8182;

pub const VALKEY_URI: &str = "redis://127.0.0.1:6379";

pub const VS_ZPR_ADDR: Ipv6Addr = Ipv6Addr::new(
    0xfd5a, 0x5052, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, // fd5a:5052::1
);
