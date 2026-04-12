use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use parking_lot::RwLock;

const NUM_SHARDS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceAlert {
    pub source_ip: String,
    pub target_port: u16,
    pub attempt_count: u32,
    pub timestamp: i64,
}

struct Shard {
    /// tracks attempts: (Source IP, Target Port) -> (Last Attempt Time, Count)
    attempts: HashMap<(String, u16), (DateTime<Utc>, u32)>,
    threshold: u32,
    window_secs: i64,
}

impl Shard {
    fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            threshold: 15, // Lowered threshold slightly for home networks
            window_secs: 60,
        }
    }

    fn check(&mut self, source_ip: &str, target_port: u16) -> Option<BruteForceAlert> {
        let now = Utc::now();
        let key = (source_ip.to_string(), target_port);
        let entry = self.attempts.entry(key).or_insert((now, 0));

        if (now - entry.0).num_seconds() > self.window_secs {
            entry.0 = now;
            entry.1 = 1;
        } else {
            entry.1 += 1;
        }

        if entry.1 >= self.threshold {
            let count = entry.1;
            entry.1 = 0; // Reset
            
            Some(BruteForceAlert {
                source_ip: source_ip.to_string(),
                target_port,
                attempt_count: count,
                timestamp: now.timestamp_millis(),
            })
        } else {
            None
        }
    }

    fn cleanup(&mut self) {
        let now = Utc::now();
        let window_secs = self.window_secs;
        self.attempts.retain(|_, (last_time, _)| {
            (now - *last_time).num_seconds() < window_secs * 2
        });
    }
}

pub struct BruteForceDetector {
    shards: Vec<RwLock<Shard>>,
}

impl BruteForceDetector {
    pub fn new() -> Self {
        let shards = (0..NUM_SHARDS).map(|_| RwLock::new(Shard::new())).collect();
        Self { shards }
    }

    fn get_shard_index(ip: &str) -> usize {
        ip.bytes()
            .fold(0usize, |acc, b| acc.wrapping_add(b as usize))
            % NUM_SHARDS
    }

    pub fn check(&self, source_ip: &str, target_port: u16) -> Option<BruteForceAlert> {
        // Broaden sensitive ports detection range
        match target_port {
             21 | 22 | 23 | 3389 | 5900 | 80 | 443 | 8080 | 8443 => (),
            _ => return None,
        }

        let shard_idx = Self::get_shard_index(source_ip);
        self.shards[shard_idx].write().check(source_ip, target_port)
    }

    pub fn cleanup(&self) {
        for shard in &self.shards {
            shard.write().cleanup();
        }
    }
}

impl Default for BruteForceDetector {
    fn default() -> Self {
        Self::new()
    }
}
