use crate::anomaly::portscan::{PortScanAlert, PortScanDetector};
use crate::sniffer::packet::{PacketInfo, Protocol};
use chrono::Utc;
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tokio::sync::broadcast;
use tracing::info;

const MAX_ALERTS: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: i64,
    pub alert_type: AlertType,
    pub source_ip: String,
    pub target_ip: Option<String>,
    pub message: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertType {
    NewDevice,
    PortScan,
    SuspiciousTraffic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Alert {
    pub fn new_device(mac: String) -> Self {
        Self {
            id: format!("alert-{}", Utc::now().timestamp_millis()),
            timestamp: Utc::now().timestamp_millis(),
            alert_type: AlertType::NewDevice,
            source_ip: mac.clone(),
            target_ip: None,
            message: format!("New device detected on network: {}", mac),
            severity: Severity::Info,
        }
    }

    pub fn port_scan(alert: PortScanAlert) -> Self {
        Self {
            id: format!("scan-{}", Utc::now().timestamp_millis()),
            timestamp: Utc::now().timestamp_millis(),
            alert_type: AlertType::PortScan,
            source_ip: alert.source_ip.clone(),
            target_ip: None,
            message: format!(
                "Port scan detected from {} - {} ports scanned",
                alert.source_ip, alert.port_count
            ),
            severity: Severity::Warning,
        }
    }
}

impl std::fmt::Display for AlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertType::NewDevice => write!(f, "New Device"),
            AlertType::PortScan => write!(f, "Port Scan"),
            AlertType::SuspiciousTraffic => write!(f, "Suspicious Traffic"),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Warning => write!(f, "Warning"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

pub struct AnomalyDetector {
    port_scan_detector: RwLock<PortScanDetector>,
    recent_alerts: RwLock<VecDeque<Alert>>,
    alert_tx: broadcast::Sender<Alert>,
    packet_batch_size: usize,
}

impl AnomalyDetector {
    pub fn new(alert_tx: broadcast::Sender<Alert>) -> Self {
        Self {
            port_scan_detector: RwLock::new(PortScanDetector::new()),
            recent_alerts: RwLock::new(VecDeque::with_capacity(MAX_ALERTS)),
            alert_tx,
            packet_batch_size: 128, // Process 128 packets at once
        }
    }

    /// Create a new anomaly detector with custom batch settings
    pub fn with_batch_settings(
        alert_tx: broadcast::Sender<Alert>,
        packet_batch_size: usize,
        _max_batch_delay_ms: u64,
    ) -> Self {
        Self {
            port_scan_detector: RwLock::new(PortScanDetector::new()),
            recent_alerts: RwLock::new(VecDeque::with_capacity(MAX_ALERTS)),
            alert_tx,
            packet_batch_size,
        }
    }

    pub fn analyze(&self, packet: &PacketInfo) {
        if packet.protocol == Protocol::Tcp {
            if let Some(dst_port) = packet.dst_port {
                let scan_alert = {
                    let detector = self.port_scan_detector.read();
                    detector.check(&packet.src_ip.to_string(), dst_port, true)
                };

                if let Some(scan_alert) = scan_alert {
                    let alert = Alert::port_scan(scan_alert);
                    info!("{}", alert.message);

                    let mut alerts = self.recent_alerts.write();
                    if alerts.len() >= MAX_ALERTS {
                        alerts.pop_front();
                    }
                    alerts.push_back(alert.clone());

                    let _ = self.alert_tx.send(alert);
                }
            }
        }
    }

    /// Batch analyze packets with Rayon parallelization
    pub fn batch_analyze(&self, packets: &[PacketInfo]) -> Vec<Alert> {
        let alerts: Vec<Alert> = packets
            .par_iter()
            .filter_map(|packet| {
                if packet.protocol == Protocol::Tcp {
                    if let Some(dst_port) = packet.dst_port {
                        let scan_alert = {
                            let detector = self.port_scan_detector.read();
                            detector.check(&packet.src_ip.to_string(), dst_port, true)
                        };

                        if let Some(scan_alert) = scan_alert {
                            Some(Alert::port_scan(scan_alert))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Add alerts to recent alerts and broadcast
        for alert in &alerts {
            info!("{}", alert.message);

            let mut recent = self.recent_alerts.write();
            if recent.len() >= MAX_ALERTS {
                recent.pop_front();
            }
            recent.push_back(alert.clone());

            let _ = self.alert_tx.send(alert.clone());
        }

        alerts
    }

    /// Process packets in batches with parallel analysis
    pub fn process_packets_parallel(&self, packets: Vec<PacketInfo>) -> Vec<Alert> {
        if packets.len() <= self.packet_batch_size {
            self.batch_analyze(&packets)
        } else {
            // Process in batches to avoid memory issues with large datasets
            packets
                .chunks(self.packet_batch_size)
                .flat_map(|chunk| self.batch_analyze(chunk))
                .collect()
        }
    }

    pub fn cleanup(&self) {
        self.port_scan_detector.read().cleanup();
    }

    pub fn get_recent_alerts(&self) -> Vec<Alert> {
        self.recent_alerts.read().iter().cloned().collect()
    }
}
