//! ZPR and related constants.
//! TODO: This needs to be reorganized.

use std::net::Ipv6Addr;

pub const VSAPI_PORT: u16 = 5002;

pub const ADMIN_HTTPS_PORT: u16 = 8182;

pub const VALKEY_URI: &str = "redis://127.0.0.1:6379";

pub const VS_ZPR_ADDR: Ipv6Addr = Ipv6Addr::new(
    0xfd5a, 0x5052, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, // fd5a:5052::1
);

pub const MAX_CLOCK_SKEW_SECS: u64 = 180;

pub const KATTR_CN: &str = "endpoint.zpr.adapter.cn";
pub const KATTR_ADDR: &str = "zpr.addr";
pub const KATTR_SUBSTRATE_ADDR: &str = "zpr.substrate_addr";
pub const KATTR_CONNECT_VIA: &str = "zpr.connect_via";
pub const KATTR_ROLE: &str = "zpr.role";

pub const ROLE_ADAPTER: &str = "adapter";
pub const ROLE_NODE: &str = "node";
