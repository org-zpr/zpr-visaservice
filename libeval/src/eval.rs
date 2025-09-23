use crate::actor::Actor;
use crate::packet::{PacketDesc, ip_proto};
use crate::zpr_policy::ZprPolicy;
use ::polio::policy_capnp;

use std::net;
use thiserror::Error;
use tracing::debug;

/// The result of evaluating a policy against a communicating pair of
/// actors and a description of the packet.
///
/// Note that this does not select a winner when where are multiple
/// policy hits.  The hits are returned in policy order.
#[derive(Debug)]
pub enum EvalDecision {
    /// Takes an explanator string.
    NoMatch(String),

    /// All matching allow permissions are returned.
    Allow(Vec<Hit>),

    /// All matching deny permissions are returned.
    Deny(Vec<Hit>),
}

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// A "hit" is a single matching permission or deny line in policy
/// that matches against the actors and packet description.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Hit {
    /// Index into the policies for the matching policy.
    /// Caller can use this to find the ZPL line and the conditions.
    match_idx: usize,

    /// If TRUE this the Hit was on the "forward" client->service direction.
    forward: bool,

    /// If there is a signal attached to this permission it is returned here.
    signal: Option<Signal>,
}

impl Hit {
    fn new_no_signal(index: usize, forward: bool) -> Self {
        Hit {
            match_idx: index,
            forward,
            signal: None,
        }
    }
    #[allow(dead_code)]
    fn new_with_signal(index: usize, forward: bool, signal: Signal) -> Self {
        Hit {
            match_idx: index,
            forward,
            signal: Some(signal),
        }
    }
}

/// VisaProps is most of the information needed to create a visa.
/// Does not set an expiration unless one is part of a policy constraint.
#[derive(Debug)]
#[allow(dead_code)]
pub struct VisaProps {
    source_addr: net::IpAddr,
    dest_addr: net::IpAddr,
    protocol: u8,
    source_port: u16,
    dest_port: u16,
    constraints: Option<Vec<Constraint>>,
    comm_opts: Option<Vec<CommOpt>>,
    zpl: String,
}

/// Policy may include constraints on the permission.
#[derive(Debug)]
pub enum Constraint {
    /// unix time milliseconds for expiration of permission.
    ExpiresAtMs(u64),
}

/// Policy may dictate certain communication pattern options.
#[derive(Debug)]
pub enum CommOpt {
    // TODO: How to use this?
    ReversePinhole,
    // others TBD?
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Signal {
    message: String,
    service: String,
}

// TODO: Not yet sure if this is useful. Maybe the context can build up
// some cache or something to make future eval calls faster?
pub struct EvalContext {
    policy: ZprPolicy,
}

#[derive(Debug, PartialEq, Eq)]
enum ScopeMatchType {
    Forward,
    Reverse,
}

enum PAttrValue {
    Atom(String),
    Set(Vec<String>),
}

impl PAttrValue {
    fn is_empty(&self) -> bool {
        match self {
            PAttrValue::Atom(s) => s.is_empty(),
            PAttrValue::Set(vs) => vs.is_empty(),
        }
    }

    fn as_slice(&self) -> &[String] {
        match self {
            PAttrValue::Atom(s) => std::slice::from_ref(s),
            PAttrValue::Set(vs) => vs.as_slice(),
        }
    }
}

impl EvalContext {
    pub fn new(policy: ZprPolicy) -> Self {
        EvalContext { policy }
    }

    /// Caller must ensure that the two actors passed here are the ones
    /// involved in the communication described by `request`.
    pub fn eval_request(
        &self,
        src_actor: &Actor,
        dst_actor: &Actor,
        request: &PacketDesc,
    ) -> Result<EvalDecision, EvalError> {
        if request.protocol != ip_proto::TCP && request.protocol != ip_proto::UDP {
            return Ok(EvalDecision::NoMatch(
                "only TCP/UDP protocols supported at the moment".into(),
            ));
        }

        let policy = self
            .policy
            .policy_rdr
            .get_root::<policy_capnp::policy::Reader>()?;
        if !policy.has_com_policies() {
            return Ok(EvalDecision::NoMatch(
                "no communication policies defined".into(),
            ));
        }

        // We will make two passes, once looking for denies, and then looking for allows (if needed).
        let deny_hits = self.match_policies(false, src_actor, dst_actor, request, &policy)?;
        if !deny_hits.is_empty() {
            return Ok(EvalDecision::Deny(deny_hits));
        }

        let allow_hits = self.match_policies(true, src_actor, dst_actor, request, &policy)?;
        // Different hits will have different constraints etc. We'll leave the picking of the
        // policy to apply to the caller.
        if !allow_hits.is_empty() {
            return Ok(EvalDecision::Allow(allow_hits));
        }
        Ok(EvalDecision::NoMatch("no matching policy".into()))
    }

    pub fn visa_info_for_hit(
        &self,
        hit: &Hit,
        request: &PacketDesc,
    ) -> Result<VisaProps, EvalError> {
        let policy = self
            .policy
            .policy_rdr
            .get_root::<policy_capnp::policy::Reader>()?;

        let matched_pol = policy.get_com_policies().unwrap().get(hit.match_idx as u32);

        if !matched_pol.get_allow() {
            return Err(EvalError::InvalidRequest(
                "visa_info_for_hit called on a deny".into(),
            ));
        }

        let match_source_port;
        let match_dest_port;

        match request.protocol {
            // For TCP/UDP if request was using a high numberd "client" port, grant the visa for
            // any client port.
            ip_proto::TCP | ip_proto::UDP => {
                if hit.forward {
                    if request.source_port > 1023 {
                        match_source_port = 0;
                    } else {
                        match_source_port = request.source_port;
                    }
                    match_dest_port = request.dest_port;
                } else {
                    if request.dest_port > 1023 {
                        match_dest_port = 0;
                    } else {
                        match_dest_port = request.dest_port;
                    }
                    match_source_port = request.source_port;
                };
            }
            _ => {
                return Err(EvalError::UnsupportedProtocol(
                    "only TCP/UDP protocols supported at the moment".into(),
                ));
            }
        }

        Ok(VisaProps {
            source_addr: request.source_addr,
            dest_addr: request.dest_addr,
            protocol: request.protocol,
            source_port: match_source_port,
            dest_port: match_dest_port,
            constraints: None, // TODO
            comm_opts: None,   // TODO
            zpl: matched_pol.get_zpl().unwrap().to_string().unwrap(),
        })
    }

    fn match_policies(
        &self,
        allows: bool,
        src_actor: &Actor,
        dst_actor: &Actor,
        request: &PacketDesc,
        policy: &policy_capnp::policy::Reader,
    ) -> Result<Vec<Hit>, EvalError> {
        let mut hits = Vec::new();
        for (i, com_policy) in policy.get_com_policies().unwrap().iter().enumerate() {
            if allows != com_policy.get_allow() {
                continue;
            }
            if allows {
                debug!("trying to match allow policy #{i}");
            } else {
                debug!("trying to match deny policy #{i}");
            }

            match self.try_match_scope(request, &com_policy) {
                Some(ScopeMatchType::Forward) => {
                    // Source -> Dest match
                    // So requesting dest port matches a service.
                    // Proceed only if the destination provides a service.
                    if !dst_actor.is_provider() {
                        debug!("policy #{i} matches FWD but dest actor is not a provider");
                        continue;
                    }
                    debug!("policy #{i} matches FWD scope");
                    // This policy matches only if all conditions match.
                    if self.match_policy_conditions(src_actor, dst_actor, &com_policy) {
                        // TODO: Signal is not yet spported in v2 binary.
                        debug!("policy #{i} hits FWD");
                        hits.push(Hit::new_no_signal(i, true));
                    }
                }
                Some(ScopeMatchType::Reverse) => {
                    // Dest -> Source match
                    // So requesting source port matches a service (is this a reply?)
                    // Proceed only if the source provides a service.
                    if !src_actor.is_provider() {
                        debug!("policy #{i} matches REV but src actor is not a provider");
                        continue;
                    }
                    debug!("policy #{i} matches REV scope");
                    // This policy matches only if all conditions match.
                    if self.match_policy_conditions(dst_actor, src_actor, &com_policy) {
                        // TODO: Signal is not yet spported in v2 binary.
                        debug!("policy #{i} hits REV");
                        hits.push(Hit::new_no_signal(i, false));
                    }
                }
                None => (),
            };
        }
        debug!("matched {} policies", hits.len());
        Ok(hits)
    }

    fn match_policy_conditions(
        &self,
        client_actor: &Actor,
        server_actor: &Actor,
        com_policy: &policy_capnp::c_policy::Reader,
    ) -> bool {
        // All conditions must match for the policy to match.
        if com_policy.has_client_conds() {
            for cond in com_policy.get_client_conds().unwrap() {
                if !self.match_condition_to_actor(&cond, client_actor) {
                    debug!("-- client condition not met: {:?}", cond);
                    return false;
                }
            }
        }
        if com_policy.has_service_conds() {
            for cond in com_policy.get_service_conds().unwrap() {
                if !self.match_condition_to_actor(&cond, server_actor) {
                    debug!("-- service condition not met: {:?}", cond);
                    return false;
                }
            }
        }
        true
    }

    /// Returns TRUE if the policy condition is satisfied by the actor.
    fn match_condition_to_actor(
        &self,
        cond: &policy_capnp::attr_expr::Reader,
        actor: &Actor,
    ) -> bool {
        let value = if !cond.has_value() {
            None
        } else {
            let val_list = cond.get_value().unwrap();
            if val_list.len() == 0 {
                None
            } else if val_list.len() == 1 {
                Some(PAttrValue::Atom(
                    val_list.get(0).unwrap().to_str().unwrap().into(),
                ))
            } else {
                Some(PAttrValue::Set(
                    val_list
                        .iter()
                        .map(|v| v.unwrap().to_str().unwrap().into())
                        .collect(),
                ))
            }
        };
        let key = cond.get_key().unwrap().to_str().unwrap();

        match cond.get_op().unwrap() {
            policy_capnp::AttrOp::Eq => {
                match value {
                    None => {
                        // Hmm... KEY, EQ, NONE ?? Is this valid?
                        if actor.has_attribute_named(key) {
                            return false;
                        }
                    }
                    Some(PAttrValue::Set(_)) => {
                        // EQ with a set is not supported for now.
                        return false;
                    }
                    Some(PAttrValue::Atom(s)) => {
                        if !actor.has_attribute_value(key, s.as_str()) {
                            return false;
                        }
                    }
                }
            }
            policy_capnp::AttrOp::Ne => {
                match value {
                    None => {
                        // Hmm... KEY, NE, NONE ?? Is this valid?
                        if !actor.has_attribute_named(key) {
                            return false;
                        }
                    }
                    Some(PAttrValue::Set(_)) => {
                        // NE with a set is not supported for now.
                        return false;
                    }
                    Some(PAttrValue::Atom(s)) => {
                        if actor.has_attribute_value(key, s.as_str()) {
                            return false;
                        }
                    }
                }
            }
            policy_capnp::AttrOp::Has => {
                let blank = match value {
                    None => true,
                    Some(ref v) => v.is_empty(),
                };
                if blank {
                    // This means we match if the actor has the attribute key present.
                    if !actor.has_attribute_named(key) {
                        return false;
                    }
                } else {
                    // HAS means the actor must have all the values set here.
                    if !actor.has_attribute_values(key, value.as_ref().unwrap().as_slice()) {
                        return false;
                    }
                }
            }
            policy_capnp::AttrOp::Excludes => {
                // Any values in here must not be present in the actor.
                if actor.has_any_attribute_values(key, value.as_ref().unwrap().as_slice()) {
                    return false;
                }
            }
        };
        true
    }

    fn try_match_scope<'a>(
        &self,
        request: &PacketDesc,
        com_policy: &policy_capnp::c_policy::Reader<'a>,
    ) -> Option<ScopeMatchType> {
        // Each policy line describes access to a service.
        for scope in com_policy.get_scope().unwrap().iter() {
            if scope.get_protocol() != request.protocol {
                continue;
            }
            let scope_match_type = match scope.which() {
                Ok(policy_capnp::scope::Port(pnum)) => {
                    let allow_service_port_num = pnum.get_port_num();
                    if request.source_port == allow_service_port_num {
                        Some(ScopeMatchType::Reverse)
                    } else if request.dest_port == allow_service_port_num {
                        Some(ScopeMatchType::Forward)
                    } else {
                        None
                    }
                }
                Ok(policy_capnp::scope::PortRange(pr)) => {
                    let lowport = pr.get_low();
                    let highport = pr.get_high();
                    if request.dest_port >= lowport && request.dest_port <= highport {
                        Some(ScopeMatchType::Forward)
                    } else if request.source_port >= lowport && request.source_port <= highport {
                        Some(ScopeMatchType::Reverse)
                    } else {
                        None
                    }
                }
                Err(::capnp::NotInSchema(_)) => None,
            };
            if scope_match_type.is_none() {
                continue;
            }
            let scope_match_type = scope_match_type.unwrap();

            // If we are UDP and the UDP-one-way flag is set, then reverse match is not permitted.
            if request.protocol == ip_proto::UDP && scope_match_type == ScopeMatchType::Reverse {
                match scope.get_flag() {
                    Ok(policy_capnp::ScopeFlag::UdpOneWay) => {
                        // Reverse not allowed, this is a one-way UDP service.
                        continue;
                    }
                    _ => (),
                }
            }

            // I don't think we need to check all the scopes once we get a match.
            return Some(scope_match_type);
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::actor;
    use bytes::Bytes;
    use std::time::Duration;
    use std::{path::Path, sync::Once};
    use tracing::Level;
    use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

    static TRACING_INIT: Once = Once::new();

    fn setup() {
        TRACING_INIT.call_once(|| {
            tracing_subscriber::registry()
                .with(fmt::layer().with_thread_ids(true))
                .with(LevelFilter::from_level(Level::DEBUG))
                .init();
        });
    }

    /// Load a binary policy by name from the tests/zpl directory.
    fn load_policy(pname: &str) -> ZprPolicy {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let pname = Path::new(manifest_dir)
            .join("tests")
            .join("zpl")
            .join(pname);
        let encoded = std::fs::read(pname).unwrap();
        let encoded_container_bytes = Bytes::from(encoded);
        let container_reader = capnp::serialize::read_message(
            &mut std::io::Cursor::new(&encoded_container_bytes),
            capnp::message::ReaderOptions::new(),
        )
        .unwrap();
        let container = container_reader
            .get_root::<policy_capnp::policy_container::Reader>()
            .unwrap();
        if !container.has_policy() {
            panic!("policy container missing 'policy' field");
        }
        let policy_bytes = container.get_policy().unwrap();
        ZprPolicy::new_from_policy_bytes(Bytes::copy_from_slice(policy_bytes)).unwrap()
    }

    #[test]
    fn test_basic_eval() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(pol);

        // should let red users access content:red databases.
        let mut user = Actor::new();
        user.add_attr("user.zpr.tag", "user.red", Duration::from_secs(60));

        let mut service = Actor::new();
        service.add_attr(actor::KATTR_SERVICES, "database", Duration::from_secs(60));
        service.add_attr("service.content", "red", Duration::from_secs(60));
        let packet = PacketDesc::new_tcp_req("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80);

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            EvalDecision::Allow(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 1);
                assert!(hits[0].forward);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }

        // Should deny access to green tagged users.
        let mut green_user = Actor::new();
        green_user.add_attr("user.zpr.tag", "user.green", Duration::from_secs(60));
        let decision = ctx.eval_request(&green_user, &service, &packet).unwrap();
        match decision {
            EvalDecision::Deny(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].match_idx, 0);
                assert!(hits[0].forward);
            }
            _ => panic!("expected deny decision, not {:?}", decision),
        }
    }

    #[test]
    fn test_visa_info() {
        setup();
        let pol = load_policy("basic.bin2");
        let ctx = EvalContext::new(pol);

        // should let red users access content:red databases.
        let mut user = Actor::new();
        user.add_attr("user.zpr.tag", "user.red", Duration::from_secs(60));

        let mut service = Actor::new();
        service.add_attr(actor::KATTR_SERVICES, "database", Duration::from_secs(60));
        service.add_attr("service.content", "red", Duration::from_secs(60));
        let packet = PacketDesc::new_tcp_req("fd5a:5052:3000::1", "fd5a:5052:3000::2", 12345, 80);

        let decision = ctx.eval_request(&user, &service, &packet).unwrap();
        match decision {
            EvalDecision::Allow(hits) => {
                assert_eq!(hits.len(), 1);
                let vinfo = ctx.visa_info_for_hit(&hits[0], &packet).unwrap();
                assert_eq!(vinfo.zpl, "zpl_missing"); // TODO: compiler does not write the ZPL yet.
                assert_eq!(vinfo.source_addr, packet.source_addr);
                assert_eq!(vinfo.dest_addr, packet.dest_addr);
                assert_eq!(vinfo.protocol, packet.protocol);
                assert_eq!(vinfo.source_port, 0); // high port becomes 0
                assert_eq!(vinfo.dest_port, 80);
            }
            _ => panic!("expected allow decision, not {:?}", decision),
        }
    }
}
