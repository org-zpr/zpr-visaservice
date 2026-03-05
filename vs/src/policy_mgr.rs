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
use tracing::{debug, info};

use crate::db;
use crate::error::StoreError;
use crate::logging::targets::MAIN;

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
    ) -> Result<Self, StoreError> {
        debug!(target: MAIN, "initializing policy manager");
        policy.set_vinst(1);

        let _db_updated = repo.set_current_policy(&policy, false).await?;

        debug!(target: MAIN, "policy manager initialized successfully");
        Ok(PolicyMgr {
            inner: ArcSwap::from_pointee(policy),
            repo,
        })
    }

    /// Create a new policy manager, initializing it with the current policy in the database. If there is no
    /// policy in the database, this will return an error.
    pub async fn new_from_state(repo: db::PolicyRepo) -> Result<Self, StoreError> {
        debug!(target: MAIN, "initializing policy manager from state");
        let policy = repo.get_current_policy().await?;
        info!(target: MAIN, "loaded policy from state version:{}, created:{}", policy.get_version().unwrap_or(0), 
            policy.get_created().unwrap_or("unknown").to_string());
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
    pub fn update_policy(&self, new_policy: Policy) -> Result<(), StoreError> {
        let mut np = Arc::new(new_policy);
        self.inner.rcu(move |op| {
            Arc::get_mut(&mut np).unwrap().set_vinst(op.vinst() + 1);
            np.clone()
        });
        Ok(())
    }
}
