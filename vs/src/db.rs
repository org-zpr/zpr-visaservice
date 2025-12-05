//! General database functions.

use chrono::Utc;

pub type Conn = redis::aio::ConnectionManager;

/// All database string timestamps look like this.
pub fn gen_timestamp() -> String {
    let now = Utc::now();
    now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
