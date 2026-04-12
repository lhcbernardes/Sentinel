use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    pub timestamp: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u32,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceBaseline {
    pub device_id: String,
    pub avg_bytes_per_sec: f64,
    pub avg_packets_per_sec: f64,
    pub common_ports: Vec<u16>,
    pub common_protocols: Vec<String>,
    pub stddev_bytes: f64,
    pub learned_at: i64,
}

impl Default for DeviceBaseline {
    fn default() -> Self {
        Self {
            device_id: String::new(),
            avg_bytes_per_sec: 0.0,
            avg_packets_per_sec: 0.0,
            common_ports: Vec::new(),
            common_protocols: Vec::new(),
            stddev_bytes: 0.0,
            learned_at: chrono::Utc::now().timestamp_millis(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub device_id: String,
    pub anomaly_type: AnomalyType,
    pub severity: f64,
    pub description: String,
    pub timestamp: i64,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AnomalyType {
    HighTraffic,
    UnusualPort,
    NewDevice,
    TimeAnomaly,
    DataExfiltration,
    PortScan,
    BruteForce,
    BandwidthSpike,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyThresholds {
    pub high_traffic_multiplier: f64,
    pub new_port_sensitivity: f64,
    pub exfiltration_bytes: u64,
    pub min_ports_for_scan: u32,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            high_traffic_multiplier: 3.0,
            new_port_sensitivity: 0.7,
            exfiltration_bytes: 100_000_000,
            min_ports_for_scan: 10,
        }
    }
}

pub struct MlDetector {
    baselines: HashMap<String, DeviceBaseline>,
    thresholds: AnomalyThresholds,
    recent_anomalies: VecDeque<Anomaly>,
}

impl MlDetector {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            thresholds: AnomalyThresholds::default(),
            recent_anomalies: VecDeque::with_capacity(101),
        }
    }

    pub fn analyze_packet(&mut self, device_id: &str, sample: TrafficSample) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        let baseline = self.baselines.get(device_id).cloned().unwrap_or_default();

        if baseline.avg_bytes_per_sec > 0.0 {
            let current_rate = sample.bytes_in as f64 + sample.bytes_out as f64;

            if current_rate > baseline.avg_bytes_per_sec * self.thresholds.high_traffic_multiplier {
                anomalies.push(Anomaly {
                    device_id: device_id.to_string(),
                    anomaly_type: AnomalyType::HighTraffic,
                    severity: (current_rate / baseline.avg_bytes_per_sec).min(1.0),
                    description: format!(
                        "Traffic {}x higher than baseline",
                        current_rate / baseline.avg_bytes_per_sec
                    ),
                    timestamp: sample.timestamp,
                    details: vec![format!(
                        "Current: {} bytes/s, Baseline: {} bytes/s",
                        current_rate as u64, baseline.avg_bytes_per_sec as u64
                    )],
                });
            }
        }

        for port in &sample.ports {
            if !baseline.common_ports.is_empty() && !baseline.common_ports.contains(port) {
                anomalies.push(Anomaly {
                    device_id: device_id.to_string(),
                    anomaly_type: AnomalyType::UnusualPort,
                    severity: self.thresholds.new_port_sensitivity,
                    description: format!("Unusual port {} accessed", port),
                    timestamp: sample.timestamp,
                    details: vec![format!("Port: {}", port)],
                });
            }
        }

        if sample.ports.len() as u32 >= self.thresholds.min_ports_for_scan {
            anomalies.push(Anomaly {
                device_id: device_id.to_string(),
                anomaly_type: AnomalyType::PortScan,
                severity: 0.8,
                description: format!("Possible port scan detected ({} ports)", sample.ports.len()),
                timestamp: sample.timestamp,
                details: sample
                    .ports
                    .iter()
                    .take(10)
                    .map(|p| p.to_string())
                    .collect(),
            });
        }

        if sample.bytes_out > self.thresholds.exfiltration_bytes {
            anomalies.push(Anomaly {
                device_id: device_id.to_string(),
                anomaly_type: AnomalyType::DataExfiltration,
                severity: 0.9,
                description: "Potential data exfiltration detected".to_string(),
                timestamp: sample.timestamp,
                details: vec![format!("Outbound: {} bytes", sample.bytes_out)],
            });
        }

        for anomaly in &anomalies {
            self.recent_anomalies.push_back(anomaly.clone());
        }

        while self.recent_anomalies.len() > 100 {
            self.recent_anomalies.pop_front();
        }

        anomalies
    }

    pub fn update_baseline(&mut self, device_id: &str, samples: &[TrafficSample]) {
        if samples.len() < 10 {
            return;
        }

        let total_bytes: u64 = samples.iter().map(|s| s.bytes_in + s.bytes_out).sum();
        let total_packets: u64 = samples.iter().map(|s| s.packets as u64).sum();
        let avg_bytes = total_bytes as f64 / samples.len() as f64;

        let variance: f64 = samples
            .iter()
            .map(|s| {
                let bytes = s.bytes_in + s.bytes_out;
                (bytes as f64 - avg_bytes).powi(2)
            })
            .sum::<f64>()
            / samples.len() as f64;

        let mut port_counts: HashMap<u16, usize> = HashMap::new();
        for sample in samples {
            for port in &sample.ports {
                *port_counts.entry(*port).or_insert(0) += 1;
            }
        }
        let mut common_ports: Vec<_> = port_counts
            .into_iter()
            .filter(|(_, count)| *count >= 5)
            .map(|(port, _)| port)
            .collect();
        common_ports.sort_by(|a, b| b.cmp(a));
        common_ports.truncate(20);

        self.baselines.insert(
            device_id.to_string(),
            DeviceBaseline {
                device_id: device_id.to_string(),
                avg_bytes_per_sec: avg_bytes / 60.0,
                avg_packets_per_sec: total_packets as f64 / samples.len() as f64 / 60.0,
                common_ports,
                common_protocols: vec![],
                stddev_bytes: variance.sqrt(),
                learned_at: chrono::Utc::now().timestamp_millis(),
            },
        );
    }

    pub fn get_baseline(&self, device_id: &str) -> Option<DeviceBaseline> {
        self.baselines.get(device_id).cloned()
    }

    pub fn get_recent_anomalies(&self, limit: usize) -> Vec<Anomaly> {
        self.recent_anomalies
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn set_thresholds(&mut self, thresholds: AnomalyThresholds) {
        self.thresholds = thresholds;
    }

    pub fn get_thresholds(&self) -> AnomalyThresholds {
        self.thresholds.clone()
    }

    pub fn clear_baseline(&mut self, device_id: &str) {
        self.baselines.remove(device_id);
    }

    pub fn get_all_baselines(&self) -> Vec<DeviceBaseline> {
        self.baselines.values().cloned().collect()
    }
}

impl Default for MlDetector {
    fn default() -> Self {
        Self::new()
    }
}
