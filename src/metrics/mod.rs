use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct MetricsExporter {
    packets_total: AtomicU64,
    bytes_total: AtomicU64,
    alerts_total: AtomicU64,
    blocked_queries: AtomicU64,
    dns_queries: AtomicU64,
    devices_seen: AtomicU64,
    requests_by_endpoint: RwLock<std::collections::HashMap<String, u64>>,
    response_times: RwLock<Vec<u64>>,
}

impl MetricsExporter {
    pub fn new() -> Self {
        Self {
            packets_total: AtomicU64::new(0),
            bytes_total: AtomicU64::new(0),
            alerts_total: AtomicU64::new(0),
            blocked_queries: AtomicU64::new(0),
            dns_queries: AtomicU64::new(0),
            devices_seen: AtomicU64::new(0),
            requests_by_endpoint: RwLock::new(std::collections::HashMap::with_capacity(100)),
            response_times: RwLock::new(Vec::with_capacity(1000)),
        }
    }

    pub fn increment_packets(&self) {
        self.packets_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, bytes: u64) {
        self.bytes_total.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn increment_alerts(&self) {
        self.alerts_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_blocked_dns(&self) {
        self.blocked_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_dns_queries(&self) {
        self.dns_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_devices(&self) {
        self.devices_seen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_request(&self, endpoint: &str) {
        *self
            .requests_by_endpoint
            .write()
            .entry(endpoint.to_string())
            .or_insert(0) += 1;
    }

    pub fn record_response_time(&self, ms: u64) {
        let mut times = self.response_times.write();
        times.push(ms);
        if times.len() > 1000 {
            times.drain(0..500);
        }
    }

    pub fn get_metrics(&self) -> String {
        let packets = self.packets_total.load(Ordering::Relaxed);
        let bytes = self.bytes_total.load(Ordering::Relaxed);
        let alerts = self.alerts_total.load(Ordering::Relaxed);
        let blocked = self.blocked_queries.load(Ordering::Relaxed);
        let dns = self.dns_queries.load(Ordering::Relaxed);
        let devices = self.devices_seen.load(Ordering::Relaxed);

        let endpoints = self.requests_by_endpoint.read();

        let response_times = self.response_times.read();
        let avg_response = if response_times.is_empty() {
            0.0
        } else {
            response_times.iter().sum::<u64>() as f64 / response_times.len() as f64
        };

        format!(
            r#"# HELP sentinel_packets_total Total packets processed
# TYPE sentinel_packets_total counter
sentinel_packets_total {}

# HELP sentinel_bytes_total Total bytes processed
# TYPE sentinel_bytes_total counter
sentinel_bytes_total {}

# HELP sentinel_alerts_total Total alerts generated
# TYPE sentinel_alerts_total counter
sentinel_alerts_total {}

# HELP sentinel_dns_queries_total Total DNS queries
# TYPE sentinel_dns_queries_total counter
sentinel_dns_queries_total {}

# HELP sentinel_dns_blocked_total DNS queries blocked
# TYPE sentinel_dns_blocked_total counter
sentinel_dns_blocked_total {}

# HELP sentinel_devices_seen Total devices seen
# TYPE sentinel_devices_seen gauge
sentinel_devices_seen {}

# HELP sentinel_requests_total API requests by endpoint
# TYPE sentinel_requests_total counter
{}

# HELP sentinel_response_time_avg Average response time in ms
# TYPE sentinel_response_time_avg gauge
sentinel_response_time_avg {}
"#,
            packets,
            bytes,
            alerts,
            dns,
            blocked,
            devices,
            endpoints
                .iter()
                .map(|(k, v)| format!("sentinel_requests_total{{endpoint=\"{}\"}} {}", k, v))
                .collect::<Vec<_>>()
                .join("\n"),
            avg_response
        )
    }
}

impl Default for MetricsExporter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PrometheusServer {
    #[allow(dead_code)]
    exporter: Arc<MetricsExporter>,
}

impl Default for PrometheusServer {
    fn default() -> Self {
        Self::new()
    }
}

impl PrometheusServer {
    pub fn new() -> Self {
        Self {
            exporter: Arc::new(MetricsExporter::new()),
        }
    }

    pub fn metrics_handler(exporter: Arc<MetricsExporter>) -> impl Fn() -> String {
        move || exporter.get_metrics()
    }
}
