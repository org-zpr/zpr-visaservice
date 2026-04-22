use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use libeval::attribute::Attribute;
use libeval::route::{AttrMatch, LinkId, NodeId, Route, RouteHint, RouteKind, TopologyQueryApi};

use crate::error::ServiceError;

pub struct Router {
    topology: Graph,
}

impl Router {
    pub fn new() -> Self {
        Self {
            topology: Graph::default(),
        }
    }

    // TODO: Should add node not error if it exists?
    pub fn add_node(&mut self, node_addr: &IpAddr) -> Result<(), ServiceError> {
        self.topology.add_node(node_addr)?;
        Ok(())
    }

    pub fn remove_node(&mut self, node_addr: &IpAddr) {
        let nid: NodeId = node_addr.into();
        self.topology.remove_node(&nid).ok();
    }

    pub fn add_link(
        &mut self,
        zpr_addr_a: &IpAddr,
        zpr_addr_b: &IpAddr,
        id: &LinkId,
        attributes: &[Attribute],
        cost: u32,
    ) -> Result<(), ServiceError> {
        let a = zpr_addr_a.into();
        let b = zpr_addr_b.into();
        self.topology
            .add_link(a, b, id.clone(), attributes.to_vec(), cost)?;
        Ok(())
    }

    pub fn remove_link(&mut self, id: &LinkId) {
        self.topology.remove_link(id).ok();
    }

    /// For now this assumes there is only one node.
    /// "Best" route is defined as the route with the lowest cost.  If there is a tie, one is picked arbitrarily.
    /// These routes are cached and only upadted when topology changes. So this is a O(1) operation.
    pub fn get_best_route(&self, _addr_a: &IpAddr, _addr_b: &IpAddr) -> Option<Route> {
        return Some(Route {
            kind: RouteKind::DirectSameNode {
                node_id: NodeId("fake-node".to_string()),
            },
            links: vec![],
            cost: 0,
        });
    }

    /// Returns list of routes between addr_a and addr_b that satisfy the hint.
    ///
    /// Results here are cached. Cache is cleard when topology is updated.
    pub fn get_routes(
        &self,
        addr_a: &IpAddr,
        addr_b: &IpAddr,
        hint: Option<&RouteHint>,
    ) -> Vec<Route> {
        vec![]
    }
}

impl TopologyQueryApi for Router {
    fn link_has_attr(&self, _link_id: &LinkId, _attr: &AttrMatch) -> bool {
        false
    }
}

#[derive(Debug)]
struct Node {
    edges: HashSet<LinkId>,
}

#[derive(Debug)]
struct Link {
    a: NodeId,
    b: NodeId,
    attributes: Vec<Attribute>,
    cost: u32,
}

#[derive(Debug, Default)]
struct Graph {
    nodes: HashMap<NodeId, Node>,
    edges: HashMap<LinkId, Link>,
}

impl Graph {
    fn add_node(&mut self, node_id: impl Into<NodeId>) -> Result<NodeId, ServiceError> {
        let nid = node_id.into();

        // If node exists call that an error.
        if self.nodes.contains_key(&nid) {
            return Err(ServiceError::TopologyNodeExists(nid.0));
        }

        self.nodes.insert(
            nid.clone(),
            Node {
                edges: HashSet::new(),
            },
        );
        Ok(nid)
    }

    fn add_link(
        &mut self,
        a: NodeId,
        b: NodeId,
        id: LinkId,
        attributes: Vec<Attribute>,
        cost: u32,
    ) -> Result<(), ServiceError> {
        if a == b {
            return Err(ServiceError::Topology(
                "add_link: self-links are not allowed".into(),
            ));
        }

        if !self.nodes.contains_key(&a) {
            return Err(ServiceError::Topology(format!(
                "add_link: node {:?} does not exist",
                a
            )));
        }

        if !self.nodes.contains_key(&b) {
            return Err(ServiceError::Topology(format!(
                "add_link: node {:?} does not exist",
                b
            )));
        }

        if self.edges.contains_key(&id) {
            return Err(ServiceError::TopologyLinkExists(id.0));
        }

        self.edges.insert(
            id.clone(),
            Link {
                a: a.clone(),
                b: b.clone(),
                attributes,
                cost,
            },
        );

        self.nodes.get_mut(&a).unwrap().edges.insert(id.clone());
        self.nodes.get_mut(&b).unwrap().edges.insert(id);

        Ok(())
    }

    fn link(&self, id: &LinkId) -> Option<&Link> {
        self.edges.get(id)
    }

    fn link_mut(&mut self, id: &LinkId) -> Option<&mut Link> {
        self.edges.get_mut(id)
    }

    fn neighbors(&self, node_id: &NodeId) -> Option<Vec<NodeId>> {
        let node = self.nodes.get(&node_id)?;
        let mut out = Vec::new();

        for edge_id in &node.edges {
            let edge = self.edges.get(edge_id)?;
            let other = if &edge.a == node_id {
                edge.b.clone()
            } else {
                edge.a.clone()
            };
            out.push(other);
        }

        Some(out)
    }

    /// Returns None if link not found. If link does exist then it is removed and returned.
    fn remove_link(&mut self, link_id: &LinkId) -> Result<Option<Link>, ServiceError> {
        let link = match self.edges.remove(link_id) {
            Some(link) => link,
            None => return Ok(None),
        };

        if let Some(node) = self.nodes.get_mut(&link.a) {
            node.edges.remove(link_id);
        }
        if let Some(node) = self.nodes.get_mut(&link.b) {
            node.edges.remove(link_id);
        }

        Ok(Some(link))
    }

    /// Returns None if node not found. If node does exist then it is removed and returned.
    fn remove_node(&mut self, node_id: &NodeId) -> Result<Option<Node>, ServiceError> {
        let link_ids: Vec<LinkId> = match self.nodes.get(&node_id) {
            Some(node) => node.edges.iter().cloned().collect(),
            None => return Ok(None),
        };

        for link_id in &link_ids {
            self.remove_link(link_id)?;
        }

        match self.nodes.remove(node_id) {
            Some(node) => Ok(Some(node)),
            None => Ok(None),
        }
    }

    /// Get the lowest cost path from a to b. If there are multiple this should return one of them.
    fn get_low_cost_path(&self, _a: &NodeId, _b: &NodeId) -> Option<Vec<LinkId>> {
        None
    }
}
