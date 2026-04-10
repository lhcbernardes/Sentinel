use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub struct StatsManager {
    total_packets: RwLock<u64>,
    total_bytes: RwLock<u64>,
    blocked_domains: RwLock<u64>,
    blocked_ips: RwLock<u64>,
}

impl StatsManager {
    pub fn new() -> Self {
        Self {
            total_packets: RwLock::new(0),
            total_bytes: RwLock::new(0),
            blocked_domains: RwLock::new(0),
            blocked_ips: RwLock::new(0),
        }
    }

    pub fn record_packet(&self, bytes: u32) {
        *self.total_packets.write() += 1;
        *self.total_bytes.write() += bytes as u64;
    }

    pub fn record_blocked_domain(&self) {
        *self.blocked_domains.write() += 1;
    }
    pub fn record_blocked_ip(&self) {
        *self.blocked_ips.write() += 1;
    }

    pub fn get_stats(&self) -> NetworkStats {
        NetworkStats {
            packets: *self.total_packets.read(),
            bytes: *self.total_bytes.read(),
            blocked_domains: *self.blocked_domains.read(),
            blocked_ips: *self.blocked_ips.read(),
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
