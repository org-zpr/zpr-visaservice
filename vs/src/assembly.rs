use std::sync::Arc;

use crate::connection_control::ConnectionControl;

#[allow(dead_code)]
pub struct Assembly {
    pub system_start_time: std::time::Instant,
    pub cc: ConnectionControl,
}

impl Assembly {
    pub fn new() -> Self {
        Assembly {
            system_start_time: std::time::Instant::now(),
            cc: ConnectionControl::new(),
        }
    }

    #[allow(dead_code)]
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {}
}
