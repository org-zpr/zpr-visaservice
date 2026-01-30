use ipnet::Ipv6Net;
use std::net::IpAddr;

use libeval::actor::Role;

use crate::error::VSError;

const ADAPTER_BASE_NET: &str = "fd5a:5052:adda:1::/64";
const NODE_BASE_NET: &str = "fd5a:5052:90de:1::/64";

pub struct NetMgr {
    node_net: Ipv6Net,
    adapter_net: Ipv6Net,
    node_idx: u64,
    adapter_idx: u64,
    // db
}

impl NetMgr {
    pub async fn new(/* TODO: pass a db */) -> Result<Self, VSError> {
        let adapter_net: Ipv6Net = ADAPTER_BASE_NET
            .parse()
            .expect("error in net_mgr ADAPTER_BASE_NET constant");

        let node_net: Ipv6Net = NODE_BASE_NET
            .parse()
            .expect("error in net_mgr NODE_BASE_NET constant");

        // Do we have state in the DB? If so grab next address info db.
        Ok(NetMgr {
            node_net,
            adapter_net,
            node_idx: 0,
            adapter_idx: 0,
        })
    }

    pub async fn get_next_zpr_addr(&mut self, role: Role) -> Result<IpAddr, VSError> {
        let addr = match role {
            Role::Adapter => {
                let mut next_idx = self.adapter_idx.wrapping_add(1);
                if next_idx == 0 || next_idx == u64::MAX {
                    next_idx = 1;
                }
                let ip = self.adapter_net.hosts().nth(next_idx as usize).unwrap();
                self.adapter_idx = next_idx;
                IpAddr::V6(ip)
            }
            Role::Node => {
                let mut next_idx = self.node_idx.wrapping_add(1);
                if next_idx == 0 || next_idx == u64::MAX {
                    next_idx = 1;
                }
                let ip = self.node_net.hosts().nth(next_idx as usize).unwrap();
                self.node_idx = next_idx;
                IpAddr::V6(ip)
            }
            _ => panic!("get_next_zpr_addr called with unsupported role"),
        };

        // TODO: Update redis -- write our indexes somewhere.
        Ok(addr)
    }
}
