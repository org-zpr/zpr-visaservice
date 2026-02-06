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

use arc_swap::ArcSwap;
use libeval::policy::Policy;
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

use crate::db;
use crate::error::DBError;
use crate::logging::targets::MAIN;

#[derive(Debug, Error)]
pub enum PMError {
    #[error("redis error: {0}")]
    RedisError(#[from] redis::RedisError),

    #[error("policy database error: {0}")]
    PolicyDBError(#[from] DBError),
}

#[allow(dead_code)]
pub struct PolicyMgr {
    inner: ArcSwap<Policy>,
    repo: db::PolicyRepo,
}

impl PolicyMgr {
    /// Create a new policy manager, initializing it with the given initial policy.
    /// This will store the initial policy into the database if not already present.
    ///
    /// Note that policy is written to DB for backup purposes. It is kept in memory
    /// here for general access by rest of visa service.
    pub async fn new_with_initial_policy(
        mut policy: Policy,
        repo: db::PolicyRepo,
    ) -> Result<Self, PMError> {
        debug!(target: MAIN, "initializing policy manager");
        policy.set_vinst(1);

        let _db_updated = repo.set_current_policy(&policy, false).await?;

        debug!(target: MAIN, "policy manager initialized successfully");
        Ok(PolicyMgr {
            inner: ArcSwap::from_pointee(policy),
            repo,
        })
    }

    /// Callers should drop the policy as quickly as possible to avoid missing a policy update.
    pub fn get_current(&self) -> Arc<Policy> {
        self.inner.load_full()
    }

    /// Update the current policy.  The new policy will be assigned a new version instance number (vinst)
    /// that is one greater than the current policy's vinst.
    ///
    /// TODO: There is a lot of housekeeping that needs to happen around a policy update. None of that
    /// is implemented here. Right now this is just to support unit tests.
    #[allow(dead_code)]
    pub fn update_policy(&self, new_policy: Policy) -> Result<(), PMError> {
        let mut np = Arc::new(new_policy);
        self.inner.rcu(move |op| {
            Arc::get_mut(&mut np).unwrap().set_vinst(op.vinst() + 1);
            np.clone()
        });
        Ok(())
    }
}
