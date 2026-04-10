use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct StatsManager {
    total_packets: AtomicU64,
    total_bytes: AtomicU64,
    blocked_domains: AtomicU64,
    blocked_ips: AtomicU64,
}

impl StatsManager {
    pub fn new() -> Self {
        Self {
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            blocked_domains: AtomicU64::new(0),
            blocked_ips: AtomicU64::new(0),
        }
    }

    pub fn record_packet(&self, bytes: u32) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_blocked_domain(&self) {
        self.blocked_domains.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_blocked_ip(&self) {
        self.blocked_ips.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> NetworkStats {
        NetworkStats {
            packets: self.total_packets.load(Ordering::Relaxed),
            bytes: self.total_bytes.load(Ordering::Relaxed),
            blocked_domains: self.blocked_domains.load(Ordering::Relaxed),
            blocked_ips: self.blocked_ips.load(Ordering::Relaxed),
        }
    }
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub packets: u64,
    pub bytes: u64,
    pub blocked_domains: u64,
    pub blocked_ips: u64,
}
