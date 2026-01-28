use tracing::Level;
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

/// Target of a log message, for filtering.
pub mod targets {
    pub const MAIN: &str = "main";

    /// HTTPS admin server.
    pub const HTADMIN: &str = "htadmin";

    /// The Capn Proto VS-API service.
    pub const VSAPI: &str = "vsapi";

    /// Connection Control.
    pub const CC: &str = "conctrl";

    /// Redis/ValKey store
    pub const REDIS: &str = "redisdb";

    /// Visa Manager
    pub const VMGR: &str = "visamgr";

    /// Actor Manager
    #[allow(dead_code)]
    pub const AMGR: &str = "actormgr";

    /// VSS Manager
    pub const VSSMGR: &str = "vssmgr";

    /// Visa request worker pool
    pub const VISAREQ: &str = "visareq";
}

pub fn enable_logging(verbose: bool) {
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            //.with(fmt::layer().with_thread_ids(true))
            .with(fmt::layer())
            .with(LevelFilter::from_level(level)),
    )
    .expect("failed to initialize logging");
}
