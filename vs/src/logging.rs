use tracing::Level;
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

/// Target of a log message, for filtering.
pub mod targets {
    pub const MAIN: &str = "main";
    pub const HTADMIN: &str = "htadmin";
    pub const VSAPI: &str = "vsapi";
    pub const CC: &str = "con_ctrl";
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
