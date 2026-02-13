//! Manage network type stuff like IP addresses and, maybe later, topology info.

use ipnet::{Ipv4Net, Ipv6Net};
use libeval::actor::Role;
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::config;
use crate::error::ServiceError;

/// Minimum prefix length at which IPv4 `hosts()` includes the network address
/// (RFC 3021 point-to-point links and /32 host routes).
const IPV4_POINT_TO_POINT_PREFIX_LEN: u8 = 31;

pub struct NetMgr {
    node_addrs: Arc<Mutex<dyn AddrAllocator + Send>>,
    adapter_addrs: Arc<Mutex<dyn AddrAllocator + Send>>,
}

trait AddrAllocator {
    fn allocate(&mut self) -> Option<IpAddr>;
    fn release(&mut self, addr: IpAddr) -> Result<(), ServiceError>;
    fn contains(&self, addr: IpAddr) -> bool;
}

struct Addr6Allocator {
    net: Ipv6Net,
    rng: SmallRng,
    used: HashSet<u64>,
}

struct Addr4Allocator {
    net: Ipv4Net,
    rng: SmallRng,
    used: HashSet<u32>,
}

impl NetMgr {
    /// Create a NetMgr backed by IPv6 address pools.
    pub async fn new_v6() -> Result<Self, ServiceError> {
        let adapter_net = config::ADAPTER_BASE_V6NET;
        let node_net = config::NODE_BASE_V6NET;

        // Do we have state in the DB? If so grab next address info db.
        Ok(NetMgr {
            node_addrs: Arc::new(Mutex::new(Addr6Allocator::new(node_net))),
            adapter_addrs: Arc::new(Mutex::new(Addr6Allocator::new(adapter_net))),
        })
    }

    /// Create a NetMgr backed by IPv4 address pools.
    #[allow(dead_code)]
    pub async fn new_v4() -> Result<Self, ServiceError> {
        let adapter_net = config::ADAPTER_BASE_V4NET;
        let node_net = config::NODE_BASE_V4NET;

        // Do we have state in the DB? If so grab next address info db.
        Ok(NetMgr {
            node_addrs: Arc::new(Mutex::new(Addr4Allocator::new(node_net))),
            adapter_addrs: Arc::new(Mutex::new(Addr4Allocator::new(adapter_net))),
        })
    }

    /// Return an unused, random address in our network space.
    pub async fn get_next_zpr_addr(&self, role: Role) -> Result<IpAddr, ServiceError> {
        let addr = match role {
            Role::Adapter => {
                self.adapter_addrs
                    .lock()
                    .unwrap()
                    .allocate()
                    .ok_or(ServiceError::Internal(
                        "failed to allocate adapter address".to_string(),
                    ))?
            }
            Role::Node => {
                self.node_addrs
                    .lock()
                    .unwrap()
                    .allocate()
                    .ok_or(ServiceError::Internal(
                        "failed to allocate node address".to_string(),
                    ))?
            }
            _ => panic!("get_next_zpr_addr called with unsupported role"),
        };

        // TODO: Update redis
        Ok(addr)
    }

    /// Release a previously allocated address.
    pub async fn release_zpr_addr(&self, addr: IpAddr) -> Result<(), ServiceError> {
        {
            let mut allocator = self.adapter_addrs.lock().unwrap();
            if allocator.contains(addr) {
                return allocator.release(addr);
            }
        }
        {
            let mut allocator = self.node_addrs.lock().unwrap();
            if allocator.contains(addr) {
                return allocator.release(addr);
            }
        }
        Err(ServiceError::Internal(format!(
            "attempted to release address {addr} not managed by any allocator"
        )))
    }
}

impl Addr6Allocator {
    /// Construct a new IPv6 allocator for a /64 subnet.
    fn new(net: Ipv6Net) -> Self {
        if net.prefix_len() != 64 {
            panic!("IPv6 AddrAllocator only supports /64 nets");
        }
        Addr6Allocator {
            net,
            rng: SmallRng::from_rng(&mut rand::rng()),
            used: HashSet::new(),
        }
    }
}

impl AddrAllocator for Addr6Allocator {
    fn contains(&self, addr: IpAddr) -> bool {
        if let IpAddr::V6(v6addr) = addr {
            self.net.contains(&v6addr)
        } else {
            false
        }
    }

    /// Allocate a random unused IPv6 address from the subnet.
    fn allocate(&mut self) -> Option<IpAddr> {
        for _ in 0..10_000 {
            let host: u64 = self.rng.next_u64();
            if self.used.insert(host) {
                let ip = self.net.hosts().nth(host as usize)?;
                return Some(IpAddr::V6(ip));
            }
        }
        None
    }

    /// Release a previously allocated IPv6 address.
    fn release(&mut self, addr: IpAddr) -> Result<(), ServiceError> {
        if let IpAddr::V6(v6addr) = addr {
            if !self.net.contains(&v6addr) {
                return Err(ServiceError::Internal(format!(
                    "attempted to release IPv6 address {addr} outside allocator net: {}",
                    self.net
                )));
            }
            let n = u128::from(v6addr) - u128::from(self.net.network());
            if self.used.remove(&(n as u64)) {
                Ok(())
            } else {
                Err(ServiceError::Internal(format!(
                    "attempted to release unallocated IPv6 address: {addr}"
                )))
            }
        } else {
            Err(ServiceError::Internal(
                "attempted to release non-IPv6 address from IPv6 allocator".to_string(),
            ))
        }
    }
}

impl Addr4Allocator {
    /// Construct a new IPv4 allocator for the given subnet.
    fn new(net: Ipv4Net) -> Self {
        Addr4Allocator {
            net,
            rng: SmallRng::from_rng(&mut rand::rng()),
            used: HashSet::new(),
        }
    }
}

impl AddrAllocator for Addr4Allocator {
    fn contains(&self, addr: IpAddr) -> bool {
        if let IpAddr::V4(v4addr) = addr {
            self.net.contains(&v4addr)
        } else {
            false
        }
    }

    /// Allocate a random unused IPv4 address from the subnet.
    fn allocate(&mut self) -> Option<IpAddr> {
        let host_bits = 32 - self.net.prefix_len();
        let mask = (1u32 << host_bits) - 1;

        for _ in 0..10_000 {
            let host: u32 = self.rng.next_u32() & mask;
            if self.used.insert(host) {
                let ip = self.net.hosts().nth(host as usize)?;
                return Some(IpAddr::V4(ip));
            }
        }
        None
    }

    /// Release a previously allocated IPv4 address.
    fn release(&mut self, addr: IpAddr) -> Result<(), ServiceError> {
        if let IpAddr::V4(v4addr) = addr {
            if !self.net.contains(&v4addr) {
                return Err(ServiceError::Internal(format!(
                    "attempted to release IPv4 address {addr} outside allocator net: {}",
                    self.net
                )));
            }
            let n = u32::from(v4addr) - u32::from(self.net.network());
            let host_index = if self.net.prefix_len() < IPV4_POINT_TO_POINT_PREFIX_LEN {
                n.checked_sub(1).ok_or_else(|| {
                    ServiceError::Internal(format!(
                        "attempted to release IPv4 network address: {addr}"
                    ))
                })?
            } else {
                n
            };
            if self.used.remove(&host_index) {
                Ok(())
            } else {
                Err(ServiceError::Internal(format!(
                    "attempted to release unallocated IPv4 address: {addr}"
                )))
            }
        } else {
            Err(ServiceError::Internal(
                "attempted to release non-IPv4 address from IPv4 allocator".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn v6_allocate_release_adapter_and_node() {
        let mgr = NetMgr::new_v6().await.expect("failed to build v6 NetMgr");
        let adapter_net = config::ADAPTER_BASE_V6NET;
        let node_net = config::NODE_BASE_V6NET;

        let adapter_addr = mgr
            .get_next_zpr_addr(Role::Adapter)
            .await
            .expect("failed to allocate adapter v6 addr");
        let node_addr = mgr
            .get_next_zpr_addr(Role::Node)
            .await
            .expect("failed to allocate node v6 addr");

        match adapter_addr {
            IpAddr::V6(addr) => assert!(adapter_net.contains(&addr)),
            _ => panic!("expected v6 adapter address"),
        }
        match node_addr {
            IpAddr::V6(addr) => assert!(node_net.contains(&addr)),
            _ => panic!("expected v6 node address"),
        }

        mgr.release_zpr_addr(adapter_addr)
            .await
            .expect("failed to release adapter v6 addr");
        mgr.release_zpr_addr(node_addr)
            .await
            .expect("failed to release node v6 addr");

        assert!(mgr.release_zpr_addr(adapter_addr).await.is_err());
        assert!(mgr.release_zpr_addr(node_addr).await.is_err());
    }

    #[tokio::test]
    async fn v4_allocate_release_adapter_and_node() {
        let mgr = NetMgr::new_v4().await.expect("failed to build v4 NetMgr");
        let adapter_net = config::ADAPTER_BASE_V4NET;
        let node_net = config::NODE_BASE_V4NET;

        let adapter_addr = mgr
            .get_next_zpr_addr(Role::Adapter)
            .await
            .expect("failed to allocate adapter v4 addr");
        let node_addr = mgr
            .get_next_zpr_addr(Role::Node)
            .await
            .expect("failed to allocate node v4 addr");

        match adapter_addr {
            IpAddr::V4(addr) => assert!(adapter_net.contains(&addr)),
            _ => panic!("expected v4 adapter address"),
        }
        match node_addr {
            IpAddr::V4(addr) => assert!(node_net.contains(&addr)),
            _ => panic!("expected v4 node address"),
        }

        mgr.release_zpr_addr(adapter_addr)
            .await
            .expect("failed to release adapter v4 addr");
        mgr.release_zpr_addr(node_addr)
            .await
            .expect("failed to release node v4 addr");

        assert!(mgr.release_zpr_addr(adapter_addr).await.is_err());
        assert!(mgr.release_zpr_addr(node_addr).await.is_err());
    }

    #[test]
    fn v4_allocate_release_on_slash31() {
        let net = Ipv4Net::from_str("10.0.0.0/31").unwrap();
        let mut alloc = Addr4Allocator::new(net);

        let addr = alloc.allocate().expect("failed to allocate from /31");
        match addr {
            IpAddr::V4(v4) => assert!(net.contains(&v4)),
            _ => panic!("expected v4 address"),
        }
        alloc.release(addr).expect("failed to release /31 address");
        assert!(alloc.release(addr).is_err(), "double release should fail");
    }

    #[test]
    fn v4_allocate_release_all_slash31_hosts() {
        let net = Ipv4Net::from_str("10.0.0.0/31").unwrap();
        let mut alloc = Addr4Allocator::new(net);

        // A /31 has exactly 2 usable hosts; allocate until we get both.
        let mut addrs = HashSet::new();
        for _ in 0..10_000 {
            if addrs.len() == 2 {
                break;
            }
            if let Some(addr) = alloc.allocate() {
                addrs.insert(addr);
            }
        }
        assert_eq!(addrs.len(), 2, "should allocate both /31 addresses");

        for addr in &addrs {
            alloc.release(*addr).expect("failed to release /31 address");
        }
    }

    #[test]
    fn v4_allocate_release_on_slash32() {
        let net = Ipv4Net::from_str("10.0.0.1/32").unwrap();
        let mut alloc = Addr4Allocator::new(net);

        let addr = alloc.allocate().expect("failed to allocate from /32");
        assert_eq!(addr, IpAddr::from([10, 0, 0, 1]));
        alloc.release(addr).expect("failed to release /32 address");
        assert!(alloc.release(addr).is_err(), "double release should fail");
    }

    #[test]
    fn v4_allocate_release_on_slash30() {
        let net = Ipv4Net::from_str("10.0.0.0/30").unwrap();
        let mut alloc = Addr4Allocator::new(net);

        // A /30 has 2 usable hosts (network and broadcast excluded).
        let mut addrs = HashSet::new();
        for _ in 0..10_000 {
            if addrs.len() == 2 {
                break;
            }
            if let Some(addr) = alloc.allocate() {
                addrs.insert(addr);
            }
        }
        assert_eq!(addrs.len(), 2, "should allocate both /30 host addresses");

        for addr in &addrs {
            alloc.release(*addr).expect("failed to release /30 address");
        }
    }

    #[tokio::test]
    async fn v6_allocate_release_unallocated() {
        let mgr = NetMgr::new_v6().await.expect("failed to build v6 NetMgr");
        let adapter_net = config::ADAPTER_BASE_V6NET;

        let adapter_addr: IpAddr = "fd5a:5052:adda:1:7c51:12d4:f89e:8d90"
            .parse()
            .expect("failed to parse adapter v6 addr");

        match adapter_addr {
            IpAddr::V6(addr) => assert!(adapter_net.contains(&addr)),
            _ => panic!("expected v6 adapter address"),
        }

        // Should return an error since it is not allocated
        assert!(mgr.release_zpr_addr(adapter_addr).await.is_err());
    }
}
