use serde::Serialize;
use std::net::IpAddr;

use crate::error::EvalError;
use crate::eval_result::FinalEvalResult;

#[derive(Debug)]
pub struct RouteResidualEvaluator {
    predicate: RoutePredicate,
    hint: Option<RouteHint>,
}

#[derive(Debug, Clone, Serialize, Hash, Eq, PartialEq)]
pub struct AttrMatch {} // TODO

// Answers the question: "Is this route allowed?".
// Note these are extracted from policy duing first pass.
//
// TODO: Investigate why we really need Serialize on this. Is it for ZPT?
#[derive(Debug, Serialize)]
pub enum RoutePredicate {
    True,
    DirectOnly,
    RequireLinkedPath,
    AnyLinkHas(AttrMatch),
    NoLinkHas(AttrMatch),
    AllLinksHave(AttrMatch),
    And(Vec<RoutePredicate>),
    Or(Vec<RoutePredicate>),
}

/// An optional route hint can be used by the Router to cull the set of possible routes.
/// The hint is conservative and may match more routes than are strictly possible by policy.
/// Not all policies will be able to provide a hint, and in that case all routes need
/// to be evaluated.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RouteHint {
    /// No links at all (direct connection between source and destination).
    pub direct_only: bool,

    /// Must have links (i.e. cannot be direct).
    pub require_linked_path: bool,

    /// Route is candidate if any link on the path matches
    pub any_link_has: Vec<AttrMatch>,

    /// Route is candidate if no link on the path matches
    pub no_link_has: Vec<AttrMatch>,

    /// Route is candidate if all links on the path match
    pub all_links_have: Vec<AttrMatch>,
}

/// Simple interface into the ZPR network topology that the route residual evaluator uses
/// to evaluate routes.
pub trait TopologyQueryApi {
    fn link_has_attr(&self, link_id: &LinkId, attr: &AttrMatch) -> bool;
}

#[derive(Debug, Serialize, Clone)]
pub struct Route {
    pub kind: RouteKind,
    pub links: Vec<LinkId>,
    pub cost: u32,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub String);

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct LinkId(pub String);

#[derive(Debug, Serialize, Clone)]
pub enum RouteKind {
    DirectSameNode { node_id: NodeId },
    Multihop,
}

impl From<IpAddr> for NodeId {
    fn from(addr: IpAddr) -> Self {
        NodeId(addr.to_string())
    }
}

impl From<&IpAddr> for NodeId {
    fn from(addr: &IpAddr) -> Self {
        NodeId(addr.to_string())
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        NodeId(s.to_string())
    }
}

impl From<&str> for LinkId {
    fn from(s: &str) -> Self {
        LinkId(s.to_string())
    }
}

impl Route {
    pub fn is_direct(&self) -> bool {
        matches!(self.kind, RouteKind::DirectSameNode { .. })
    }

    pub fn hop_count(&self) -> usize {
        self.links.len()
    }
}

impl RouteResidualEvaluator {
    /// An optional coarse hint that can be used to prune routes.
    pub fn hint(&self) -> Option<&RouteHint> {
        self.hint.as_ref()
    }

    // Evaluate a single candidate route against policy.
    //
    // We have previously done an eval call on the EvalContext. So we know that the actors
    // match.  But we may still need to hold on to the relevant actor attributes to make
    // the evaluation.  The assumption is that everything we need in the residual is populated
    // in it when it is created.
    //
    // Example:
    //    allow admins to access services over secure links.
    //    allow employees to access services. # implied: over any link.
    //    never allow admins to access services over insecure links.
    //
    // When this is called with a route to "services" over "insecure" link.
    // We need to know if the actor is an admin or just an employee.
    pub fn eval_route(
        &self,
        _route: &Route,
        _topology: &impl TopologyQueryApi,
    ) -> Result<FinalEvalResult, EvalError> {
        Err(EvalError::InternalError(
            "route evaluation not implemented".to_string(),
        ))
    }

    // Evaluate multiple candidate routes against policy.
    //
    // This also applies the default logic to the matches:
    // - if we match a NEVER that is a final DENY (there may be multiple hits).
    // - if we don't match any NEVERs and we match multiple ALLOWs we return a final allow (with all the hits).
    // - Else, we return a NoMatch
    pub fn eval_routes(
        &self,
        _routes: &[Route],
        _topology: &impl TopologyQueryApi,
    ) -> Result<FinalEvalResult, EvalError> {
        Err(EvalError::InternalError(
            "route evaluation not implemented".to_string(),
        ))
    }
}
