//! Counters: Track various interesting events in the visa service operations.
use dashmap::DashMap;
use enum_map::{Enum, EnumMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Counters {
    pub counters: EnumMap<CounterType, Counter>,
    per_node_counters: DashMap<IpAddr, NodeInfo>,
}

pub struct Counter {
    value: AtomicU64,
}

pub struct NodeInfo {
    counters: EnumMap<CounterType, Counter>,
    last_visa_req: std::time::Instant,
}

impl Default for NodeInfo {
    fn default() -> Self {
        Self {
            counters: EnumMap::default(),
            last_visa_req: std::time::Instant::now(),
        }
    }
}

impl Counters {
    /// Shorthand for `Counters::counters[<TYPE>].increment()`.
    pub fn incr(&self, c: CounterType) {
        self.counters[c].increment();
    }

    pub fn incr_node(&self, c: CounterType, node: &IpAddr) {
        self.per_node_counters.entry(*node).or_default().counters[c].increment();
    }

    pub fn remove_node_info(&self, node: &IpAddr) {
        self.per_node_counters.remove(node);
    }

    pub fn update_request_time(&self, node: &IpAddr) {
        self.per_node_counters
            .entry(*node)
            .or_default()
            .last_visa_req = std::time::Instant::now();
    }

    #[allow(dead_code)]
    pub fn get_last_request_time(&self, node: &IpAddr) -> Option<std::time::Instant> {
        match self.per_node_counters.get(node) {
            Some(node_info) => Some(node_info.last_visa_req),
            None => None,
        }
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
