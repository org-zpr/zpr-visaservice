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
use std::sync::atomic::{AtomicU64, Ordering};

#[allow(dead_code)]
pub struct PolicyMgr {
    // Although the policy holds a copy of the `vinst` it is this PolicyMgr that is
    // the source of truth for it.  When a policy is updated the PolicyMgr sets the
    // correct value in the Policy.
    vinst: AtomicU64,
    inner: ArcSwap<Policy>,
}

impl PolicyMgr {
    pub fn new_with_initial_policy(mut policy: Policy) -> Self {
        policy.set_vinst(1);
        PolicyMgr {
            inner: ArcSwap::from_pointee(policy),
            vinst: AtomicU64::new(1),
        }
    }

    /// Callers should drop the policy as quickly as possible to avoid missing a policy update.
    pub fn get_current(&self) -> Arc<Policy> {
        self.inner.load_full()
    }

    /// Update the current policy.  The new policy will be assigned a new version instance number.
    #[allow(dead_code)]
    fn update_policy(&self, mut new_policy: Policy) {
        let prev_vinst = self.vinst.fetch_add(1, Ordering::Relaxed);
        new_policy.set_vinst(prev_vinst + 1);
        self.inner.store(Arc::new(new_policy));
    }
}
