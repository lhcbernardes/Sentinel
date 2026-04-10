use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const WINDOW_SECONDS: i64 = 5;
const SYN_THRESHOLD: usize = 10;

#[derive(Debug, Clone)]
struct SynEntry {
    timestamp: i64,
    port: u16,
}

pub struct PortScanDetector {
    syn_history: std::collections::HashMap<String, VecDeque<SynEntry>>,
}

impl PortScanDetector {
    pub fn new() -> Self {
        Self {
            syn_history: std::collections::HashMap::new(),
        }
    }

    pub fn check(&mut self, src_ip: &str, port: u16, is_syn: bool) -> Option<PortScanAlert> {
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

    pub fn cleanup(&mut self) {
        let now = chrono::Utc::now().timestamp_millis();
        self.syn_history.retain(|_, v| {
            v.retain(|e| now - e.timestamp < WINDOW_SECONDS * 1000);
            !v.is_empty()
        });
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
