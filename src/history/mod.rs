use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const MAX_SAMPLES: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    pub timestamp: i64,
    pub packets: u64,
    pub bytes: u64,
}

pub struct HistoryManager {
    samples: RwLock<VecDeque<TrafficSample>>,
}

impl HistoryManager {
    pub fn new() -> Self {
        Self {
            samples: RwLock::new(VecDeque::new()),
        }
    }

    pub fn record(&self, packets: u64, bytes: u64) {
        let mut s = self.samples.write();
        if s.len() >= MAX_SAMPLES {
            s.pop_front();
        }
        s.push_back(TrafficSample {
            timestamp: chrono::Utc::now().timestamp_millis(),
            packets,
            bytes,
        });
    }

    pub fn get_recent(&self, count: usize) -> Vec<TrafficSample> {
        self.samples
            .read()
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    pub fn get_stats(&self) -> HistoryStats {
        let s = self.samples.read();
        let total_packets: u64 = s.iter().map(|x| x.packets).sum();
        let total_bytes: u64 = s.iter().map(|x| x.bytes).sum();
        HistoryStats {
            total_samples: s.len(),
            total_packets,
            total_bytes,
        }
    }
}

impl Default for HistoryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryStats {
    pub total_samples: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentStats {
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub active_connections: usize,
}

impl Default for CurrentStats {
    fn default() -> Self {
        Self {
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
            active_connections: 0,
        }
    }
}
