use std::sync::Arc;
use tokio::time::{self, Instant};
use tracing::{error, trace, warn};

use crate::assembly::Assembly;
use crate::config;
use crate::db::LockDescriptor;

pub async fn launch(asm: Arc<Assembly>, vslock: LockDescriptor) {
    let mut last_renewed = Instant::now();
    let mut interval = time::interval(config::VALKEY_LOCK_REFRESH_SECS);
    loop {
        interval.tick().await;
        match asm.state_db.acquire_or_renew_lock(&vslock).await {
            Ok(true) => {
                last_renewed = Instant::now();
                interval = time::interval(config::VALKEY_LOCK_REFRESH_SECS);
                trace!("vs db lock renewed");
            }
            Ok(false) => {
                error!("vs db lock lost, shutting down");
                // TODO: signal shutdown to main loop instead of just panicing?
                panic!("vs db lock lost");
            }
            Err(e) => {
                let age = last_renewed.elapsed();
                // If the next retry attempt could arrive after the lock has already
                // expired, shut down now rather than risk another instance taking
                // the lock while we are still running.
                if age + config::VALKEY_LOCK_RETRY_SECS >= config::VALKEY_LOCK_TIMEOUT {
                    error!(
                        "vs db lock renewal failing for {:?}, lock expiry imminent, shutting down: {:?}",
                        age, e
                    );
                    panic!("vs db lock expiry imminent");
                }
                warn!(
                    "failed to renew vs db lock (last renewed {:?} ago), retrying in {:?}: {:?}",
                    age,
                    config::VALKEY_LOCK_RETRY_SECS,
                    e
                );
                interval = time::interval(config::VALKEY_LOCK_RETRY_SECS);
            }
        }
    }
}
