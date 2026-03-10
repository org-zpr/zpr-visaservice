use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{error, trace, warn};

use crate::assembly::Assembly;
use crate::config;
use crate::db::LockDescriptor;

pub async fn launch(asm: Arc<Assembly>, vslock: LockDescriptor) {
    let mut last_renewed = Instant::now();
    let mut delay = config::VALKEY_LOCK_REFRESH_SECS;
    loop {
        tokio::time::sleep(delay).await;
        match asm.state_db.acquire_or_renew_lock(&vslock).await {
            Ok(true) => {
                last_renewed = Instant::now();
                delay = config::VALKEY_LOCK_REFRESH_SECS;
                trace!("vs db lock renewed");
            }
            Ok(false) => {
                error!("vs db lock lost, shutting down");
                // TODO: signal shutdown to main loop instead of just panicing?
                error!("vs db lock lost");
                process::exit(1);
            }
            Err(e) => {
                let age = last_renewed.elapsed();
                // If the next retry attempt could arrive after the lock has already
                // expired, shut down now rather than risk another instance taking
                // the lock while we are still running.
                if age + config::VALKEY_LOCK_RETRY_SECS
                    >= config::VALKEY_LOCK_TIMEOUT + Duration::from_secs(1)
                {
                    error!(
                        "vs db lock renewal failing for {:?}, lock expiry imminent, shutting down: {:?}",
                        age, e
                    );
                    error!("vs db lock expiry imminent");
                    process::exit(1);
                }
                warn!(
                    "failed to renew vs db lock (last renewed {:?} ago), retrying in {:?}: {:?}",
                    age,
                    config::VALKEY_LOCK_RETRY_SECS,
                    e
                );
                delay = config::VALKEY_LOCK_RETRY_SECS;
            }
        }
    }
}
