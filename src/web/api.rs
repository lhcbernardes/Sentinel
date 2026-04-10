use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub blocks_active: bool,
    pub dns_enabled: bool,
    pub packet_count: u64,
    pub device_count: usize,
    pub alert_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientListResponse {
    pub clients: Vec<ClientInfo>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub id: String,
    pub name: Option<String>,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub group: String,
    pub dns_queries: u64,
    pub blocked: u64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryResponse {
    pub queries: Vec<DnsQuery>,
    pub total: usize,
    pub blocked_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub timestamp: i64,
    pub client_ip: String,
    pub domain: String,
    pub blocked: bool,
    pub block_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStatsResponse {
    pub total_bytes: u64,
    pub total_packets: u64,
    pub bytes_per_second: f64,
    pub packets_per_second: f64,
    pub top_protocols: Vec<(String, u64)>,
    pub top_talkers: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistResponse {
    pub trackers: usize,
    pub malware: usize,
    pub attackers: usize,
    pub custom: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleResponse {
    pub rules: Vec<AlertRuleInfo>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleInfo {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub condition: String,
    pub action: String,
    pub triggered_count: u32,
}

pub struct ApiHandler {
    rate_limit: std::sync::atomic::AtomicU64,
    #[allow(dead_code)]
    rate_limit_window_secs: u64,
    rate_limit_max: u64,
}

impl ApiHandler {
    pub fn new() -> Self {
        Self {
            rate_limit: std::sync::atomic::AtomicU64::new(0),
            rate_limit_window_secs: 60,
            rate_limit_max: 100,
        }
    }

    pub fn check_rate_limit(&self, client_ip: &str) -> bool {
        let current = self.rate_limit.load(std::sync::atomic::Ordering::Relaxed);

        if current >= self.rate_limit_max {
            tracing::warn!("Rate limit exceeded for {}", client_ip);
            return false;
        }

        self.rate_limit
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    pub fn reset_rate_limit(&self) {
        self.rate_limit
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for ApiHandler {
    fn default() -> Self {
        Self::new()
    }
}
