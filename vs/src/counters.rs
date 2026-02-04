//! Counters: Track various interesting events in the visa service operations.

use enum_map::{Enum, EnumMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Counters {
    pub counters: EnumMap<CounterType, Counter>,
}

pub struct Counter {
    value: AtomicU64,
}

impl Counters {
    /// Shorthand for `Counters::counters[<TYPE>].increment()`.
    pub fn incr(&self, c: CounterType) {
        self.counters[c].increment();
    }
}

impl Counter {
    pub fn new() -> Self {
        Counter {
            value: AtomicU64::new(0),
        }
    }

    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_count(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Enum, Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum CounterType {
    VisaRequests,
    VisaRequestsApproved,
    VisaRequestsDenied,
    VisaRequestQueueFull,
    VisaRequestTimeout,
    VisaRequestQueueError,
    VisaRequestFailed, // internal unspecified error of some sort

    VsApiVisaRequests,
    VsApiPings,

    VssErrors,

    NodeConnectionsSuccess,
    NodeConnectionsFailed,

    AdapterConnectionsSuccess,
    AdapterConnectionsFailed,
}

impl CounterType {
    pub fn name(&self) -> &'static str {
        match self {
            CounterType::VisaRequests => "visa_requests_total",
            CounterType::VisaRequestsApproved => "visa_requests_approved",
            CounterType::VisaRequestsDenied => "visa_requests_denied",
            CounterType::VisaRequestQueueError => "visa_request_queue_error",
            CounterType::VisaRequestTimeout => "visa_request_timeout",
            CounterType::VisaRequestQueueFull => "visa_request_queue_full",
            CounterType::VisaRequestFailed => "visa_request_failed",
            CounterType::VsApiVisaRequests => "vsapi_visa_requests",
            CounterType::VsApiPings => "vsapi_pings",
            CounterType::VssErrors => "vss_errors",
            CounterType::NodeConnectionsSuccess => "node_connections_success",
            CounterType::NodeConnectionsFailed => "node_connections_failed",
            CounterType::AdapterConnectionsSuccess => "adapter_connections_success",
            CounterType::AdapterConnectionsFailed => "adapter_connections_failed",
        }
    }
}

impl fmt::Display for CounterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
