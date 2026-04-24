//! Router keeps track of nodes and their connections. It does not know anything about adapters.
//! So to route between two actors you first need to determine their docking nodes.  Then you
//! can query this Router to see if there is a path.
//!
//! Must be kept in sync with the coming and going of nodes, and for each node the coming and
//! going of links. (TODO)

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;

use libeval::attribute::{AttrMatch, Attribute};
use libeval::eval_route::{RouteHint, TopologyQueryApi};
use libeval::route::{LinkId, NodeId, Route, RouteKind};

use crate::error::TopologyError;

/// Memoization key for [Router::get_routes].
///
/// ## Route cache strategy
///
/// `get_routes` runs a DFS over the full topology to enumerate all simple paths between two
/// nodes, which is expensive on large or dense graphs.  Results are stored in
/// `RouterInner::route_cache` keyed by `(src, dst, hint)`.
///
/// ### Targeted invalidation
///
/// `RouterInner` maintains one reverse index:
///
/// - **`link_to_cache_keys`** — maps each `LinkId` → set of cache keys whose routes traverse
///   that link.  `remove_link` uses this to evict only the entries that actually use the
///   removed link.  `remove_node` uses it transitively via the node's incident links.
///
/// The index is populated in `get_routes` at cache-insert time and cleaned up atomically
/// by `RouterInner::invalidate_keys` whenever entries are evicted.
///
/// ### add_link always flushes the full cache
///
/// Targeted invalidation on link *removal* is exact: any affected route must traverse the
/// removed link, so `link_to_cache_keys` identifies the precise affected set.
///
/// Link *addition* is different.  A new link a-b can create routes for pairs (x, y) whose
/// previously cached routes never touched a or b at all (e.g. x→a and b→y existed but
/// a-b did not, so the only cached route was direct x→y).  Determining which pairs could
/// gain new routes would require a full graph traversal — no cheaper exact answer exists.
/// `add_link` therefore flushes the entire route cache.
///
/// ### Ordering constraint
///
/// `invalidate_keys` walks `topology.edges` to resolve a `LinkId` → `(node_a, node_b)` for
/// link-index cleanup.  It must therefore be called **before** the topology mutation that
/// removes the link/node, otherwise those entries are gone and the index leaks stale entries.
#[derive(Hash, Eq, PartialEq, Clone)]
struct RouteCacheKey {
    a: NodeId,
    b: NodeId,
    hint: Option<RouteHint>,
}

struct RouterInner {
    topology: Graph,
    route_cache: HashMap<RouteCacheKey, Vec<Route>>,
    /// Reverse index: cache keys whose routes traverse a given link. See [RouteCacheKey].
    link_to_cache_keys: HashMap<LinkId, HashSet<RouteCacheKey>>,
}

impl RouterInner {
    /// Removes a set of cache keys and cleans up `link_to_cache_keys` for each removed entry.
    ///
    /// Must be called before any topology mutation that removes links, because it resolves
    /// `LinkId` → endpoints via `topology.edges`.  Duplicate keys are safe — a missing
    /// `route_cache` entry is a no-op.
    fn invalidate_keys(&mut self, keys: impl IntoIterator<Item = RouteCacheKey>) {
        for key in keys {
            let Some(routes) = self.route_cache.remove(&key) else {
                continue;
            };
            let affected_links: HashSet<LinkId> = routes
                .iter()
                .flat_map(|r| r.links.iter().cloned())
                .collect();
            for link_id in &affected_links {
                if let Some(s) = self.link_to_cache_keys.get_mut(link_id) {
                    s.remove(&key);
                    if s.is_empty() {
                        self.link_to_cache_keys.remove(link_id);
                    }
                }
            }
        }
    }
}

pub struct Router {
    inner: Mutex<RouterInner>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RouterInner {
                topology: Graph::default(),
                route_cache: HashMap::new(),
                link_to_cache_keys: HashMap::new(),
            }),
        }
    }

    /// Adds a node to the Routers view of the network topology.
    /// Nodes are identified by their IP address.
    /// Nodes are all alone until links are added that include them.
    ///
    ///TODO: This does error if nodes exists... should we instead just merge it in?
    ///
    /// ## Errors
    /// - If node already exists then this returns [TopologyError::NodeExists]
    pub fn add_node(&self, node_addr: &IpAddr) -> Result<(), TopologyError> {
        let mut inner = self.inner.lock().unwrap();
        inner.topology.add_node(node_addr)?;
        Ok(())
    }

    /// Removes a node and all its incident links from the topology.
    pub fn remove_node(&self, node_addr: &IpAddr) {
        let mut inner = self.inner.lock().unwrap();
        let nid: NodeId = node_addr.into();

        // Phase 1: evict entries whose routes traverse any of the node's incident links.
        // Collect the union of link_to_cache_keys for each incident link first to avoid
        // simultaneous borrows.
        let incident_link_ids: Vec<LinkId> = inner
            .topology
            .nodes
            .get(&nid)
            .map(|n| n.edges.iter().cloned().collect())
            .unwrap_or_default();
        let keys: Vec<RouteCacheKey> = incident_link_ids
            .iter()
            .flat_map(|lid| {
                inner
                    .link_to_cache_keys
                    .get(lid)
                    .into_iter()
                    .flat_map(|s| s.iter().cloned())
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        inner.invalidate_keys(keys);

        // Phase 2: scan for entries where the node is an explicit endpoint.  These arise
        // when compute_routes returned an empty Vec (no links → phase 1 finds nothing).
        let endpoint_keys: Vec<RouteCacheKey> = inner
            .route_cache
            .keys()
            .filter(|k| k.a == nid || k.b == nid)
            .cloned()
            .collect();
        inner.invalidate_keys(endpoint_keys);

        // Topology mutation comes last — invalidate_keys needs topology.edges intact.
        inner.topology.remove_node(&nid);
    }

    /// Adds a link between the two nodes identified by the given IP addresses.
    /// The two nodes must be distinct and must already exist in the topology.
    ///
    /// ## Errors
    /// - If attempt to create link from a node to itself then this returns [TopologyError::LinkToSelf]
    /// - If a or b do not exist returns [TopologyError::NodeNotFound]
    /// - If link id already exists then this returns [TopologyError::LinkExists]
    ///
    #[allow(dead_code)]
    pub fn add_link(
        &self,
        zpr_addr_a: &IpAddr,
        zpr_addr_b: &IpAddr,
        id: &LinkId,
        attributes: &[Attribute],
        cost: u32,
    ) -> Result<(), TopologyError> {
        let mut inner = self.inner.lock().unwrap();
        let a: NodeId = zpr_addr_a.into();
        let b: NodeId = zpr_addr_b.into();

        // A new link can create routes for pairs whose cached routes never touched a or b
        // (e.g. dormant x→a and b→y segments now form x→a→b→y).  Identifying all affected
        // pairs would require a full graph traversal, so we flush the entire cache instead.
        inner.route_cache.clear();
        inner.link_to_cache_keys.clear();

        inner
            .topology
            .add_link(a, b, id.clone(), attributes.to_vec(), cost)?;
        Ok(())
    }

    /// Remove a link by its id. If the link does not exist this is a no-op.
    #[allow(dead_code)]
    pub fn remove_link(&self, id: &LinkId) {
        let mut inner = self.inner.lock().unwrap();

        // Only evict entries that actually traverse this specific link — routes on
        // completely disjoint parts of the topology are unaffected.
        // Collect before calling invalidate_keys to release the shared borrow.
        let keys: Vec<RouteCacheKey> = inner
            .link_to_cache_keys
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();

        // Invalidation must precede topology.remove_link so that topology.edges still
        // contains the link's endpoint info needed for node-index cleanup.
        inner.invalidate_keys(keys);
        inner.link_to_cache_keys.remove(id);

        inner.topology.remove_link(id);
    }

    /// "Best" route is defined as the route with the lowest cost. If there is a tie, one is picked arbitrarily.
    /// These routes are cached and only updated when topology changes.
    pub fn get_best_route(&self, addr_a: &IpAddr, addr_b: &IpAddr) -> Option<Route> {
        let a: NodeId = addr_a.into();
        let b: NodeId = addr_b.into();
        if a == b {
            return Some(Route {
                kind: RouteKind::DirectSameNode { node_id: a },
                links: vec![],
                cost: 0,
            });
        }
        let inner = self.inner.lock().unwrap();
        let (links, cost) = inner.topology.get_low_cost_path(&a, &b)?;
        Some(Route {
            kind: RouteKind::Multihop,
            links,
            cost,
        })
    }

    /// Returns list of routes between addr_a and addr_b that satisfy the hint.
    ///
    /// Results are cached; only the affected subset of the cache is invalidated when the
    /// topology changes.  See [RouteCacheKey] for the full caching strategy.
    pub fn get_routes(
        &self,
        addr_a: &IpAddr,
        addr_b: &IpAddr,
        hint: Option<&RouteHint>,
    ) -> Vec<Route> {
        let key = RouteCacheKey {
            a: addr_a.into(),
            b: addr_b.into(),
            hint: hint.cloned(),
        };
        let mut inner = self.inner.lock().unwrap();
        if let Some(routes) = inner.route_cache.get(&key) {
            return routes.clone();
        }
        let routes = Self::compute_routes(&inner.topology, addr_a, addr_b, hint);

        // Populate link_to_cache_keys so remove_link can do targeted eviction.
        for route in &routes {
            for link_id in &route.links {
                inner
                    .link_to_cache_keys
                    .entry(link_id.clone())
                    .or_default()
                    .insert(key.clone());
            }
        }

        inner.route_cache.insert(key, routes.clone());
        routes
    }

    /// Unlike `get_best_route` this returns all the routes between addr_a and addr_b.
    /// If the optional hint is provided it is used to reduce the set of returned routes. (not yet implemented)
    ///
    /// For now the hint is ignored.
    /// TODO implement ZPL for route policy and then build this out.
    fn compute_routes(
        topology: &Graph,
        addr_a: &IpAddr,
        addr_b: &IpAddr,
        _hint: Option<&RouteHint>,
    ) -> Vec<Route> {
        let a: NodeId = addr_a.into();
        let b: NodeId = addr_b.into();
        if a == b {
            return vec![Route {
                kind: RouteKind::DirectSameNode { node_id: a },
                links: vec![],
                cost: 0,
            }];
        }
        topology
            .get_all_paths(&a, &b)
            .into_iter()
            .map(|(links, cost)| Route {
                kind: RouteKind::Multihop,
                links,
                cost,
            })
            .collect()
    }
}

impl TopologyQueryApi for Router {
    /// TODO: We do not yet support policy on link attributes and [AttrMatch] is not yet defined. This alwayes returns false.
    fn link_has_attr(&self, _link_id: &LinkId, _attr: &AttrMatch) -> bool {
        false
    }
}

#[derive(Debug)]
struct Node {
    edges: HashSet<LinkId>,
}

#[allow(dead_code)]
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
    best_routes: HashMap<(NodeId, NodeId), (Vec<LinkId>, u32)>,
}

impl Graph {
    /// Add a node into the graph. Node is all alone unless a link is added that includes it.
    ///
    /// ## Errors
    /// - If node already exists then this returns [TopologyError::NodeExists]
    fn add_node(&mut self, node_id: impl Into<NodeId>) -> Result<NodeId, TopologyError> {
        let nid = node_id.into();

        // If node exists call that an error.
        if self.nodes.contains_key(&nid) {
            return Err(TopologyError::NodeExists(nid.0));
        }

        self.nodes.insert(
            nid.clone(),
            Node {
                edges: HashSet::new(),
            },
        );
        Ok(nid)
    }

    /// Add a link between two nodes. The two nodes must be distinct.
    ///
    /// ## Errors
    /// - If attempt to create link from a node to itself then this returns [TopologyError::LinkToSelf]
    /// - If a or b do not exist returns [TopologyError::NodeNotFound]
    /// - If link id already exists then this returns [TopologyError::LinkExists]
    fn add_link(
        &mut self,
        a: NodeId,
        b: NodeId,
        id: LinkId,
        attributes: Vec<Attribute>,
        cost: u32,
    ) -> Result<(), TopologyError> {
        if a == b {
            return Err(TopologyError::LinkToSelf(
                "add_link: self-links are not allowed".into(),
            ));
        }

        if !self.nodes.contains_key(&a) {
            return Err(TopologyError::NodeNotFound(format!(
                "add_link: node {:?} does not exist",
                a
            )));
        }

        if !self.nodes.contains_key(&b) {
            return Err(TopologyError::NodeNotFound(format!(
                "add_link: node {:?} does not exist",
                b
            )));
        }

        if self.edges.contains_key(&id) {
            return Err(TopologyError::LinkExists(id.0));
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
        self.recompute();

        Ok(())
    }

    /// Look up a link by id. Returns `None` if not found.
    #[allow(dead_code)]
    fn link(&self, id: &LinkId) -> Option<&Link> {
        self.edges.get(id)
    }

    /// Look up a link by id for mutation. Returns `None` if not found.
    #[allow(dead_code)]
    fn link_mut(&mut self, id: &LinkId) -> Option<&mut Link> {
        self.edges.get_mut(id)
    }

    /// Returns all nodes directly connected to `node_id` by a single link, or `None` if the node does not exist.
    #[allow(dead_code)]
    fn neighbors(&self, node_id: &NodeId) -> Option<Vec<NodeId>> {
        let node = self.nodes.get(node_id)?;
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

    /// Remove a link from the edge map and from both endpoint nodes' edge sets without triggering a recompute.
    /// Used internally so callers can batch multiple removals before calling `recompute` once.
    fn remove_link_impl(&mut self, link_id: &LinkId) -> Option<Link> {
        let link = self.edges.remove(link_id)?;
        if let Some(node) = self.nodes.get_mut(&link.a) {
            node.edges.remove(link_id);
        }
        if let Some(node) = self.nodes.get_mut(&link.b) {
            node.edges.remove(link_id);
        }
        Some(link)
    }

    /// Returns None if link not found. If link does exist then it is removed and returned.
    fn remove_link(&mut self, link_id: &LinkId) -> Option<Link> {
        let result = self.remove_link_impl(link_id);
        self.recompute();
        result
    }

    /// Returns None if node not found. If node does exist then it is removed and returned.
    fn remove_node(&mut self, node_id: &NodeId) -> Option<Node> {
        let link_ids: Vec<LinkId> = match self.nodes.get(node_id) {
            Some(node) => node.edges.iter().cloned().collect(),
            None => return None,
        };

        for link_id in &link_ids {
            self.remove_link_impl(link_id);
        }

        let result = self.nodes.remove(node_id);
        self.recompute();
        result
    }

    /// Get the lowest cost path from a to b. If there are multiple this should return one of them.
    fn get_low_cost_path(&self, a: &NodeId, b: &NodeId) -> Option<(Vec<LinkId>, u32)> {
        self.best_routes.get(&(a.clone(), b.clone())).cloned()
    }

    /// Return every simple path from `start` to `end` (no repeated nodes).
    fn get_all_paths(&self, start: &NodeId, end: &NodeId) -> Vec<(Vec<LinkId>, u32)> {
        let mut results = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(start.clone());
        self.dfs_all_paths(start, end, &mut visited, &mut vec![], 0, &mut results);
        results
    }

    /// Recursive DFS helper for `get_all_paths`. Extends `path` one link at a time,
    /// records a result when `current == end`, and backtracks on return.
    fn dfs_all_paths(
        &self,
        current: &NodeId,
        end: &NodeId,
        visited: &mut HashSet<NodeId>,
        path: &mut Vec<LinkId>,
        cost: u32,
        results: &mut Vec<(Vec<LinkId>, u32)>,
    ) {
        if current == end {
            results.push((path.clone(), cost));
            return;
        }
        let Some(node) = self.nodes.get(current) else {
            return;
        };
        for link_id in &node.edges {
            let Some(link) = self.edges.get(link_id) else {
                continue;
            };
            let neighbor = if &link.a == current { &link.b } else { &link.a };
            if !visited.contains(neighbor) {
                visited.insert(neighbor.clone());
                path.push(link_id.clone());
                self.dfs_all_paths(
                    neighbor,
                    end,
                    visited,
                    path,
                    cost.saturating_add(link.cost),
                    results,
                );
                path.pop();
                visited.remove(neighbor);
            }
        }
    }

    /// Recompute the `best_routes` cache by running Dijkstra from every node.
    /// Called after any topology change (add/remove node or link).
    fn recompute(&mut self) {
        self.best_routes.clear();
        let starts: Vec<NodeId> = self.nodes.keys().cloned().collect();
        for start in &starts {
            for (dest, path_and_cost) in self.dijkstra_from(start) {
                self.best_routes
                    .insert((start.clone(), dest), path_and_cost);
            }
        }
    }

    /// Run Dijkstra from `start` and return, for each reachable destination, the
    /// ordered sequence of link ids on the shortest path and its total cost.
    fn dijkstra_from(&self, start: &NodeId) -> HashMap<NodeId, (Vec<LinkId>, u32)> {
        let mut dist: HashMap<NodeId, u32> = HashMap::new();
        let mut prev: HashMap<NodeId, LinkId> = HashMap::new();
        let mut heap: BinaryHeap<Reverse<(u32, NodeId)>> = BinaryHeap::new();

        dist.insert(start.clone(), 0);
        heap.push(Reverse((0, start.clone())));

        while let Some(Reverse((cost, node))) = heap.pop() {
            if cost > *dist.get(&node).unwrap_or(&u32::MAX) {
                continue;
            }

            let Some(node_data) = self.nodes.get(&node) else {
                continue;
            };
            for link_id in &node_data.edges {
                let Some(link) = self.edges.get(link_id) else {
                    continue;
                };
                let neighbor = if link.a == node { &link.b } else { &link.a };
                let next_cost = cost.saturating_add(link.cost);
                if next_cost < *dist.get(neighbor).unwrap_or(&u32::MAX) {
                    dist.insert(neighbor.clone(), next_cost);
                    prev.insert(neighbor.clone(), link_id.clone());
                    heap.push(Reverse((next_cost, neighbor.clone())));
                }
            }
        }

        let mut result = HashMap::new();
        for dest in dist.keys() {
            if dest == start {
                continue;
            }
            let mut path = vec![];
            let mut cur = dest.clone();
            while let Some(link_id) = prev.get(&cur) {
                let link = self.edges.get(link_id).unwrap();
                path.push(link_id.clone());
                cur = if link.a == cur {
                    link.b.clone()
                } else {
                    link.a.clone()
                };
            }
            if &cur == start {
                path.reverse();
                result.insert(dest.clone(), (path, dist[dest]));
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn make_router_abc() -> (Router, IpAddr, IpAddr, IpAddr) {
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let c = ip("10.0.0.3");
        let r = Router::new();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        r.add_node(&c).unwrap();
        (r, a, b, c)
    }

    fn no_hint() -> RouteHint {
        RouteHint {
            direct_only: false,
            require_linked_path: false,
            any_link_has: vec![],
            no_link_has: vec![],
            all_links_have: vec![],
        }
    }

    #[test]
    fn test_direct_same_node() {
        let a = ip("10.0.0.1");
        let r = Router::new();
        r.add_node(&a).unwrap();
        let route = r.get_best_route(&a, &a).unwrap();
        assert!(route.is_direct());
        assert_eq!(route.cost, 0);
        assert!(route.links.is_empty());
    }

    #[test]
    fn test_single_link() {
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 5).unwrap();
        let route = r.get_best_route(&a, &b).unwrap();
        assert!(!route.is_direct());
        assert_eq!(route.cost, 5);
        assert_eq!(route.links, vec![LinkId("ab".into())]);
    }

    #[test]
    fn test_multihop() {
        let (r, a, b, c) = make_router_abc();
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 1).unwrap();
        r.add_link(&b, &c, &LinkId("bc".into()), &[], 1).unwrap();
        let route = r.get_best_route(&a, &c).unwrap();
        assert!(!route.is_direct());
        assert_eq!(route.cost, 2);
        assert_eq!(route.links, vec![LinkId("ab".into()), LinkId("bc".into())]);
    }

    #[test]
    fn test_prefers_lower_cost() {
        let (r, a, b, c) = make_router_abc();
        r.add_link(&a, &b, &LinkId("ab-direct".into()), &[], 10)
            .unwrap();
        r.add_link(&a, &c, &LinkId("ac".into()), &[], 3).unwrap();
        r.add_link(&c, &b, &LinkId("cb".into()), &[], 3).unwrap();
        let route = r.get_best_route(&a, &b).unwrap();
        assert_eq!(route.cost, 6);
        assert_eq!(route.links, vec![LinkId("ac".into()), LinkId("cb".into())]);
    }

    #[test]
    fn test_unreachable() {
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        assert!(r.get_best_route(&a, &b).is_none());
    }

    #[test]
    fn test_compute_routes_returns_all_paths() {
        // A-B, B-C, A-C: routes from A to C should include both A-B-C and A-C.
        let (r, a, b, c) = make_router_abc();
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 1).unwrap();
        r.add_link(&b, &c, &LinkId("bc".into()), &[], 1).unwrap();
        r.add_link(&a, &c, &LinkId("ac".into()), &[], 5).unwrap();
        let hint = no_hint();
        let routes = r.get_routes(&a, &c, Some(&hint));
        assert_eq!(routes.len(), 2);
        let mut link_sets: Vec<Vec<LinkId>> = routes.into_iter().map(|r| r.links).collect();
        link_sets.sort_by_key(|v| v.iter().map(|l| l.0.clone()).collect::<Vec<_>>());
        assert_eq!(
            link_sets,
            vec![
                vec![LinkId("ab".into()), LinkId("bc".into())],
                vec![LinkId("ac".into())],
            ]
        );
    }

    #[test]
    fn test_route_cache_invalidated_after_remove_link() {
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 1).unwrap();
        let hint = no_hint();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
        r.remove_link(&LinkId("ab".into()));
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 0);
    }

    #[test]
    fn test_route_cache_invalidated_after_add_link() {
        // Cache is warmed with an empty result, then add_link must bust it so the new route appears.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        let hint = no_hint();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 0);
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 1).unwrap();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
    }

    #[test]
    fn test_route_cache_invalidated_after_remove_node() {
        // Cache is warmed with a route through an intermediate node; removing that node must bust the cache.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let c = ip("10.0.0.3");
        let r = Router::new();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        r.add_node(&c).unwrap();
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 1).unwrap();
        r.add_link(&b, &c, &LinkId("bc".into()), &[], 1).unwrap();
        let hint = no_hint();
        assert_eq!(r.get_routes(&a, &c, Some(&hint)).len(), 1);
        r.remove_node(&b);
        assert_eq!(r.get_routes(&a, &c, Some(&hint)).len(), 0);
    }

    #[test]
    fn test_route_cache_not_disturbed_by_add_node() {
        // Adding an isolated node must not invalidate existing cached routes between other nodes.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let d = ip("10.0.0.4");
        let r = Router::new();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 1).unwrap();
        let hint = no_hint();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
        r.add_node(&d).unwrap();
        // Route a->b still valid and served from cache.
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
        // New isolated node d has no routes to a.
        assert_eq!(r.get_routes(&a, &d, Some(&hint)).len(), 0);
    }

    #[test]
    fn test_targeted_invalidation_preserves_unrelated_entries() {
        // Removing link a-b must not evict the cached route for the disjoint pair c-d.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let c = ip("10.0.0.3");
        let d = ip("10.0.0.4");
        let r = Router::new();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        r.add_node(&c).unwrap();
        r.add_node(&d).unwrap();
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 1).unwrap();
        r.add_link(&c, &d, &LinkId("cd".into()), &[], 1).unwrap();
        let hint = no_hint();
        // Warm both cache entries.
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
        assert_eq!(r.get_routes(&c, &d, Some(&hint)).len(), 1);
        // Removing link ab should evict (a,b) but leave (c,d) intact.
        r.remove_link(&LinkId("ab".into()));
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 0);
        assert_eq!(r.get_routes(&c, &d, Some(&hint)).len(), 1);
    }

    #[test]
    fn test_empty_result_invalidated_by_add_link() {
        // A cached "unreachable" empty result must be evicted when add_link creates a path.
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        let hint = no_hint();
        // Warm cache with empty result (no path exists yet).
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 0);
        // Adding a link between a and b must bust the stale empty entry.
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 1).unwrap();
        assert_eq!(r.get_routes(&a, &b, Some(&hint)).len(), 1);
    }

    #[test]
    fn test_add_link_bridge_invalidates_unrelated_cached_pair() {
        // Regression: add_link(a,b) must evict a cached (x,y) entry even when the previously
        // cached routes for (x,y) never traversed a or b, if adding a-b creates a new path
        // x→a→b→y via pre-existing x-a and b-y links.
        let x = ip("10.0.0.10");
        let y = ip("10.0.0.20");
        let a = ip("10.0.0.1");
        let b = ip("10.0.0.2");
        let r = Router::new();
        r.add_node(&x).unwrap();
        r.add_node(&y).unwrap();
        r.add_node(&a).unwrap();
        r.add_node(&b).unwrap();
        // Direct x-y link and dormant legs x-a and b-y; no a-b yet.
        r.add_link(&x, &y, &LinkId("xy".into()), &[], 10).unwrap();
        r.add_link(&x, &a, &LinkId("xa".into()), &[], 1).unwrap();
        r.add_link(&b, &y, &LinkId("by".into()), &[], 1).unwrap();
        let hint = no_hint();
        // Warm the cache: only the direct x-y route exists.
        assert_eq!(r.get_routes(&x, &y, Some(&hint)).len(), 1);
        // Adding the bridge a-b creates a second path x→a→b→y.
        r.add_link(&a, &b, &LinkId("ab".into()), &[], 1).unwrap();
        // Cache must be invalidated; both routes should now be returned.
        assert_eq!(r.get_routes(&x, &y, Some(&hint)).len(), 2);
    }

    // --- Graph unit tests ---

    fn nid(s: &str) -> NodeId {
        NodeId(s.into())
    }

    fn lid(s: &str) -> LinkId {
        LinkId(s.into())
    }

    fn make_graph_abc() -> Graph {
        let mut g = Graph::default();
        g.add_node("a").unwrap();
        g.add_node("b").unwrap();
        g.add_node("c").unwrap();
        g
    }

    #[test]
    fn test_graph_add_node_success() {
        // Adding a new node returns its NodeId and stores the node.
        let mut g = Graph::default();
        let nid = g.add_node("a").unwrap();
        assert_eq!(nid, NodeId("a".into()));
        assert!(g.nodes.contains_key(&nid));
    }

    #[test]
    fn test_graph_add_node_duplicate_errors() {
        // Adding a node whose ID already exists returns an error.
        let mut g = Graph::default();
        g.add_node("a").unwrap();
        assert!(g.add_node("a").is_err());
    }

    #[test]
    fn test_graph_add_link_inserts_into_both_nodes() {
        // A new link is stored in the edges map and in both endpoint nodes' edge sets.
        let mut g = make_graph_abc();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
            .unwrap();
        assert!(g.edges.contains_key(&lid("ab")));
        assert!(g.nodes[&nid("a")].edges.contains(&lid("ab")));
        assert!(g.nodes[&nid("b")].edges.contains(&lid("ab")));
    }

    #[test]
    fn test_graph_add_link_self_loop_errors() {
        // A link whose two endpoints are the same node is rejected.
        let mut g = Graph::default();
        g.add_node("a").unwrap();
        assert!(
            g.add_link(nid("a"), nid("a"), lid("aa"), vec![], 1)
                .is_err()
        );
    }

    #[test]
    fn test_graph_add_link_missing_node_a_errors() {
        // A link referencing a non-existent source node is rejected.
        let mut g = Graph::default();
        g.add_node("b").unwrap();
        assert!(
            g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
                .is_err()
        );
    }

    #[test]
    fn test_graph_add_link_missing_node_b_errors() {
        // A link referencing a non-existent destination node is rejected.
        let mut g = Graph::default();
        g.add_node("a").unwrap();
        assert!(
            g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
                .is_err()
        );
    }

    #[test]
    fn test_graph_add_link_duplicate_id_errors() {
        // Inserting two links with the same ID is rejected.
        let mut g = make_graph_abc();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
            .unwrap();
        assert!(
            g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 2)
                .is_err()
        );
    }

    #[test]
    fn test_graph_remove_link_cleans_up() {
        // Removing a link returns it and clears it from both nodes' edge sets.
        let mut g = make_graph_abc();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
            .unwrap();
        let removed = g.remove_link(&lid("ab"));
        assert!(removed.is_some());
        assert!(!g.edges.contains_key(&lid("ab")));
        assert!(!g.nodes[&nid("a")].edges.contains(&lid("ab")));
        assert!(!g.nodes[&nid("b")].edges.contains(&lid("ab")));
    }

    #[test]
    fn test_graph_remove_link_not_found_returns_none() {
        // Removing a link that does not exist succeeds with Ok(None).
        let mut g = Graph::default();
        assert!(g.remove_link(&lid("nope")).is_none());
    }

    #[test]
    fn test_graph_remove_node_removes_incident_links() {
        // Removing a node removes it along with all its incident links and clears peer edge sets.
        let mut g = make_graph_abc();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(nid("a"), nid("c"), lid("ac"), vec![], 1)
            .unwrap();
        g.remove_node(&nid("a"));
        assert!(!g.nodes.contains_key(&nid("a")));
        assert!(!g.edges.contains_key(&lid("ab")));
        assert!(!g.edges.contains_key(&lid("ac")));
        assert!(g.nodes[&nid("b")].edges.is_empty());
        assert!(g.nodes[&nid("c")].edges.is_empty());
    }

    #[test]
    fn test_graph_remove_node_not_found_returns_none() {
        // Removing a node that does not exist succeeds with Ok(None).
        let mut g = Graph::default();
        assert!(g.remove_node(&nid("x")).is_none());
    }

    #[test]
    fn test_graph_neighbors_returns_connected_nodes() {
        // neighbors() returns all nodes directly connected by a link.
        let mut g = make_graph_abc();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(nid("a"), nid("c"), lid("ac"), vec![], 1)
            .unwrap();
        let mut nbrs = g.neighbors(&nid("a")).unwrap();
        nbrs.sort();
        assert_eq!(nbrs, vec![nid("b"), nid("c")]);
    }

    #[test]
    fn test_graph_neighbors_unknown_node_returns_none() {
        // neighbors() returns None when the node does not exist.
        let g = Graph::default();
        assert!(g.neighbors(&nid("x")).is_none());
    }

    #[test]
    fn test_graph_no_path_returns_none() {
        // get_low_cost_path returns None when no links connect the two nodes.
        let mut g = Graph::default();
        g.add_node("a").unwrap();
        g.add_node("b").unwrap();
        assert!(g.get_low_cost_path(&nid("a"), &nid("b")).is_none());
    }

    #[test]
    fn test_graph_single_link_path() {
        // A direct one-link path is found with the correct cost and link sequence.
        let mut g = Graph::default();
        g.add_node("a").unwrap();
        g.add_node("b").unwrap();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 7)
            .unwrap();
        let (path, cost) = g.get_low_cost_path(&nid("a"), &nid("b")).unwrap();
        assert_eq!(cost, 7);
        assert_eq!(path, vec![lid("ab")]);
    }

    #[test]
    fn test_graph_path_is_symmetric() {
        // The cost of a→b and b→a are equal (graph is undirected).
        let mut g = Graph::default();
        g.add_node("a").unwrap();
        g.add_node("b").unwrap();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 4)
            .unwrap();
        let (_, fwd) = g.get_low_cost_path(&nid("a"), &nid("b")).unwrap();
        let (_, rev) = g.get_low_cost_path(&nid("b"), &nid("a")).unwrap();
        assert_eq!(fwd, rev);
    }

    #[test]
    fn test_graph_multihop_path() {
        // A two-hop path through an intermediate node is returned in traversal order.
        let mut g = make_graph_abc();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(nid("b"), nid("c"), lid("bc"), vec![], 1)
            .unwrap();
        let (path, cost) = g.get_low_cost_path(&nid("a"), &nid("c")).unwrap();
        assert_eq!(cost, 2);
        assert_eq!(path, vec![lid("ab"), lid("bc")]);
    }

    #[test]
    fn test_graph_prefers_lower_cost_path() {
        // Dijkstra chooses the cheaper multi-hop route over a costlier direct link.
        let mut g = make_graph_abc();
        g.add_link(nid("a"), nid("b"), lid("ab-direct"), vec![], 10)
            .unwrap();
        g.add_link(nid("a"), nid("c"), lid("ac"), vec![], 3)
            .unwrap();
        g.add_link(nid("c"), nid("b"), lid("cb"), vec![], 3)
            .unwrap();
        let (path, cost) = g.get_low_cost_path(&nid("a"), &nid("b")).unwrap();
        assert_eq!(cost, 6);
        assert_eq!(path, vec![lid("ac"), lid("cb")]);
    }

    #[test]
    fn test_graph_remove_link_invalidates_route() {
        // After the only link between two nodes is removed, no path remains.
        let mut g = Graph::default();
        g.add_node("a").unwrap();
        g.add_node("b").unwrap();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
            .unwrap();
        assert!(g.get_low_cost_path(&nid("a"), &nid("b")).is_some());
        g.remove_link(&lid("ab"));
        assert!(g.get_low_cost_path(&nid("a"), &nid("b")).is_none());
    }

    #[test]
    fn test_graph_remove_intermediate_node_invalidates_route() {
        // Removing the only intermediate node on a path leaves the endpoints unreachable.
        let mut g = make_graph_abc();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 1)
            .unwrap();
        g.add_link(nid("b"), nid("c"), lid("bc"), vec![], 1)
            .unwrap();
        assert!(g.get_low_cost_path(&nid("a"), &nid("c")).is_some());
        g.remove_node(&nid("b"));
        assert!(g.get_low_cost_path(&nid("a"), &nid("c")).is_none());
    }

    #[test]
    fn test_graph_link_accessor() {
        // link() returns the stored link with correct endpoints and cost.
        let mut g = Graph::default();
        g.add_node("a").unwrap();
        g.add_node("b").unwrap();
        g.add_link(nid("a"), nid("b"), lid("ab"), vec![], 9)
            .unwrap();
        let l = g.link(&lid("ab")).unwrap();
        assert_eq!(l.a, nid("a"));
        assert_eq!(l.b, nid("b"));
        assert_eq!(l.cost, 9);
    }
}
