use libeval::policy::Policy;

use arc_swap::ArcSwap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[allow(dead_code)]
pub struct PolicyMgr {
    vinst: AtomicU64,
    inner: ArcSwap<Policy>,
}

impl PolicyMgr {
    pub fn new_with_initial_policy(policy: Policy) -> Self {
        let vinst = policy.get_vinst();
        PolicyMgr {
            inner: ArcSwap::from_pointee(policy),
            vinst: AtomicU64::new(vinst),
        }
    }

    /// Callers should drop the policy as quickly as possible to avoid missing a policy update.
    pub fn get_current(&self) -> Arc<Policy> {
        self.inner.load_full()
    }

    fn update_policy(&self, new_policy: Policy) {
        self.vinst.fetch_add(1, Ordering::Relaxed);
        self.inner.store(Arc::new(new_policy));
    }
}
