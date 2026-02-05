//! Manage network type stuff like IP addresses and, maybe later, topology info.

use ipnet::{Ipv4Net, Ipv6Net};
use libeval::actor::Role;
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::config;
use crate::error::VSError;

pub struct NetMgr {
    node_addrs: Arc<Mutex<dyn AddrAllocator + Send>>,
    adapter_addrs: Arc<Mutex<dyn AddrAllocator + Send>>,
}

trait AddrAllocator {
    fn allocate(&mut self) -> Option<IpAddr>;
    fn release(&mut self, addr: IpAddr) -> Result<(), VSError>;
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
    pub async fn new_v6() -> Result<Self, VSError> {
        let adapter_net: Ipv6Net = config::ADAPTER_BASE_V6NET
            .parse()
            .expect("error in net_mgr ADAPTER_BASE_NET constant");

        let node_net: Ipv6Net = config::NODE_BASE_V6NET
            .parse()
            .expect("error in net_mgr NODE_BASE_NET constant");

        // Do we have state in the DB? If so grab next address info db.
        Ok(NetMgr {
            node_addrs: Arc::new(Mutex::new(Addr6Allocator::new(node_net))),
            adapter_addrs: Arc::new(Mutex::new(Addr6Allocator::new(adapter_net))),
        })
    }

    /// Create a NetMgr backed by IPv4 address pools.
    #[allow(dead_code)]
    pub async fn new_v4() -> Result<Self, VSError> {
        let adapter_net: Ipv4Net = config::ADAPTER_BASE_V4NET
            .parse()
            .expect("error in net_mgr ADAPTER_BASE_NET constant");

        let node_net: Ipv4Net = config::NODE_BASE_V4NET
            .parse()
            .expect("error in net_mgr NODE_BASE_NET constant");

        // Do we have state in the DB? If so grab next address info db.
        Ok(NetMgr {
            node_addrs: Arc::new(Mutex::new(Addr4Allocator::new(node_net))),
            adapter_addrs: Arc::new(Mutex::new(Addr4Allocator::new(adapter_net))),
        })
    }

    /// Return an unused, random address in our network space.
    pub async fn get_next_zpr_addr(&self, role: Role) -> Result<IpAddr, VSError> {
        let addr = match role {
            Role::Adapter => {
                self.adapter_addrs
                    .lock()
                    .unwrap()
                    .allocate()
                    .ok_or(VSError::InternalError(
                        "failed to allocate adapter address".to_string(),
                    ))?
            }
            Role::Node => {
                self.node_addrs
                    .lock()
                    .unwrap()
                    .allocate()
                    .ok_or(VSError::InternalError(
                        "failed to allocate node address".to_string(),
                    ))?
            }
            _ => panic!("get_next_zpr_addr called with unsupported role"),
        };

        // TODO: Update redis
        Ok(addr)
    }

    /// Release a previously allocated address.
    pub async fn release_zpr_addr(&self, addr: IpAddr) -> Result<(), VSError> {
        self.adapter_addrs
            .lock()
            .unwrap()
            .release(addr)
            .or_else(|_| self.node_addrs.lock().unwrap().release(addr))
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
    fn release(&mut self, addr: IpAddr) -> Result<(), VSError> {
        if let IpAddr::V6(v6addr) = addr {
            if !self.net.contains(&v6addr) {
                return Err(VSError::InternalError(format!(
                    "attempted to release IPv6 address outside allocator net: {addr}"
                )));
            }
            let n = u128::from(v6addr) - u128::from(self.net.network());
            if self.used.remove(&(n as u64)) {
                Ok(())
            } else {
                Err(VSError::InternalError(format!(
                    "attempted to release unallocated IPv6 address: {addr}"
                )))
            }
        } else {
            Err(VSError::InternalError(
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
    fn release(&mut self, addr: IpAddr) -> Result<(), VSError> {
        if let IpAddr::V4(v4addr) = addr {
            if !self.net.contains(&v4addr) {
                return Err(VSError::InternalError(format!(
                    "attempted to release IPv4 address outside allocator net: {addr}"
                )));
            }
            let n = u32::from(v4addr) - u32::from(self.net.network());
            let host_index = if self.net.prefix_len() < 31 {
                n.checked_sub(1).ok_or_else(|| {
                    VSError::InternalError(format!(
                        "attempted to release IPv4 network address: {addr}"
                    ))
                })?
            } else {
                n
            };
            if self.used.remove(&host_index) {
                Ok(())
            } else {
                Err(VSError::InternalError(format!(
                    "attempted to release unallocated IPv4 address: {addr}"
                )))
            }
        } else {
            Err(VSError::InternalError(
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
        let adapter_net = Ipv6Net::from_str(config::ADAPTER_BASE_V6NET).unwrap();
        let node_net = Ipv6Net::from_str(config::NODE_BASE_V6NET).unwrap();

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
        let adapter_net = Ipv4Net::from_str(config::ADAPTER_BASE_V4NET).unwrap();
        let node_net = Ipv4Net::from_str(config::NODE_BASE_V4NET).unwrap();

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
}
