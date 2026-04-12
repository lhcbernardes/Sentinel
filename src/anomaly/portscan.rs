use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const WINDOW_SECONDS: i64 = 5;
const SYN_THRESHOLD: usize = 10;
const NUM_SHARDS: usize = 16;

#[derive(Debug, Clone)]
struct SynEntry {
    timestamp: i64,
    port: u16,
}

struct Shard {
    syn_history: std::collections::HashMap<String, VecDeque<SynEntry>>,
}

impl Shard {
    fn new() -> Self {
        Self {
            syn_history: std::collections::HashMap::new(),
        }
    }

    fn check(&mut self, src_ip: &str, port: u16, is_syn: bool) -> Option<PortScanAlert> {
        if !is_syn {
            return None;
        }

        let now = chrono::Utc::now().timestamp_millis();
        let entries = self.syn_history.entry(src_ip.to_string()).or_default();

        entries.push_back(SynEntry {
            timestamp: now,
            port,
        });

        entries.retain(|e| now - e.timestamp < WINDOW_SECONDS * 1000);

        if entries.len() >= SYN_THRESHOLD {
            let ports: Vec<u16> = entries.iter().map(|e| e.port).collect();
            entries.clear();

            Some(PortScanAlert {
                source_ip: src_ip.to_string(),
                port_count: ports.len(),
                ports,
            })
        } else {
            None
        }
    }

    fn cleanup(&mut self) {
        let now = chrono::Utc::now().timestamp_millis();
        self.syn_history.retain(|_, v| {
            v.retain(|e| now - e.timestamp < WINDOW_SECONDS * 1000);
            !v.is_empty()
        });
    }
}

pub struct PortScanDetector {
    shards: Vec<RwLock<Shard>>,
}

impl PortScanDetector {
    pub fn new() -> Self {
        let shards = (0..NUM_SHARDS).map(|_| RwLock::new(Shard::new())).collect();
        Self { shards }
    }

    fn get_shard_index(ip: &str) -> usize {
        ip.bytes()
            .fold(0usize, |acc, b| acc.wrapping_add(b as usize))
            % NUM_SHARDS
    }

    pub fn check(&self, src_ip: &str, port: u16, is_syn: bool) -> Option<PortScanAlert> {
        if !is_syn {
            return None;
        }

        let shard_idx = Self::get_shard_index(src_ip);
        self.shards[shard_idx].write().check(src_ip, port, is_syn)
    }

    pub fn cleanup(&self) {
        for shard in &self.shards {
            shard.write().cleanup();
        }
    }
}

impl Default for PortScanDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanAlert {
    pub source_ip: String,
    pub port_count: usize,
    pub ports: Vec<u16>,
}
