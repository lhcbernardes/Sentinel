use crate::anomaly::portscan::{PortScanAlert, PortScanDetector};
use crate::sniffer::packet::{PacketInfo, Protocol};
use chrono::Utc;
use parking_lot::RwLock;
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
}

impl AnomalyDetector {
    pub fn new(alert_tx: broadcast::Sender<Alert>) -> Self {
        Self {
            port_scan_detector: RwLock::new(PortScanDetector::new()),
            recent_alerts: RwLock::new(VecDeque::with_capacity(MAX_ALERTS)),
            alert_tx,
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

    pub fn cleanup(&self) {
        self.port_scan_detector.read().cleanup();
    }

    pub fn get_recent_alerts(&self) -> Vec<Alert> {
        self.recent_alerts.read().iter().cloned().collect()
    }
}
