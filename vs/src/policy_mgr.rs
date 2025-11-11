//! The policy manage is conceived as the one true place where the running visa service
//! can obtain the current policy.  Policy can be updated asynchronously by administrators.
//! A policy update can have many ripple effects on the running visa serivce: visas may no
//! longer be valid, connected actors may be forced to disconnect, services may be taken
//! down, node connections may change etc.
//!
//! The idea here is that clients of the policy will request it with [PolicyMgr::get_current]
//! use it as quickly as possible and then drop it.  In the case of a policy update there
//! should be few processes holding on to an old policy for long.
//!
//! The [libeval::policy::Policy] is designed to be easily cloned (as it is in an Arc) and
//! accessible by concurrent threads.

use libeval::policy::Policy;

use arc_swap::ArcSwap;
use std::sync::Arc;

#[allow(dead_code)]
pub struct PolicyMgr {
    inner: ArcSwap<Policy>,
}

impl PolicyMgr {
    pub fn new_with_initial_policy(mut policy: Policy) -> Self {
        policy.set_vinst(1);
        PolicyMgr {
            inner: ArcSwap::from_pointee(policy),
        }
    }

    /// Callers should drop the policy as quickly as possible to avoid missing a policy update.
    pub fn get_current(&self) -> Arc<Policy> {
        self.inner.load_full()
    }

    /// Update the current policy.  The new policy will be assigned a new version instance number (vinst)
    /// that is one greater than the current policy's vinst.
    #[allow(dead_code)]
    fn update_policy(&self, new_policy: Policy) {
        let mut np = Arc::new(new_policy);
        self.inner.rcu(move |op| {
            Arc::get_mut(&mut np).unwrap().set_vinst(op.vinst() + 1);
            np.clone()
        });
    }
}
