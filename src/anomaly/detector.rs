use crate::anomaly::bruteforce::{BruteForceAlert, BruteForceDetector};
use crate::anomaly::portscan::{PortScanAlert, PortScanDetector};
use crate::blocking::geoip::GeoIPService;
use crate::sniffer::packet::{PacketInfo, Protocol};
use chrono::Utc;
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
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
    BruteForce,
    SuspiciousTraffic,
    BlockedCountry,
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
    
    pub fn brute_force(alert: BruteForceAlert) -> Self {
        Self {
            id: format!("brute-{}", Utc::now().timestamp_millis()),
            timestamp: Utc::now().timestamp_millis(),
            alert_type: AlertType::BruteForce,
            source_ip: alert.source_ip.clone(),
            target_ip: None,
            message: format!(
                "Brute force attempt detected from {} on port {} ({} attempts)",
                alert.source_ip, alert.target_port, alert.attempt_count
            ),
            severity: Severity::Critical,
        }
    }

    pub fn blocked_country(source_ip: String, country: String) -> Self {
        Self {
            id: format!("geo-{}", Utc::now().timestamp_millis()),
            timestamp: Utc::now().timestamp_millis(),
            alert_type: AlertType::BlockedCountry,
            source_ip: source_ip.clone(),
            target_ip: None,
            message: format!(
                "Traffic detected from blocked country {} (IP: {})",
                country, source_ip
            ),
            severity: Severity::Critical,
        }
    }
}

impl std::fmt::Display for AlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertType::NewDevice => write!(f, "New Device"),
            AlertType::PortScan => write!(f, "Port Scan"),
            AlertType::BruteForce => write!(f, "Brute Force"),
            AlertType::BlockedCountry => write!(f, "Blocked Country"),
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
    brute_force_detector: RwLock<BruteForceDetector>,
    recent_alerts: RwLock<VecDeque<Alert>>,
    alert_tx: broadcast::Sender<Alert>,
    packet_batch_size: usize,
    geoip: RwLock<Option<Arc<GeoIPService>>>,
    blocked_countries: RwLock<Option<Arc<RwLock<std::collections::HashSet<String>>>>>,
}

impl AnomalyDetector {
    pub fn new(alert_tx: broadcast::Sender<Alert>) -> Self {
        Self {
            port_scan_detector: RwLock::new(PortScanDetector::new()),
            brute_force_detector: RwLock::new(BruteForceDetector::new()),
            recent_alerts: RwLock::new(VecDeque::with_capacity(MAX_ALERTS)),
            alert_tx,
            packet_batch_size: 128, // Process 128 packets at once
            geoip: RwLock::new(None),
            blocked_countries: RwLock::new(None),
        }
    }

    pub fn set_geoip(
        &self,
        geoip: Arc<GeoIPService>,
        blocked_countries: Arc<RwLock<std::collections::HashSet<String>>>,
    ) {
        *self.geoip.write() = Some(geoip);
        *self.blocked_countries.write() = Some(blocked_countries);
    }

    /// Create a new anomaly detector with custom batch settings
    pub fn with_batch_settings(
        alert_tx: broadcast::Sender<Alert>,
        packet_batch_size: usize,
        _max_batch_delay_ms: u64,
    ) -> Self {
        Self {
            port_scan_detector: RwLock::new(PortScanDetector::new()),
            brute_force_detector: RwLock::new(BruteForceDetector::new()),
            recent_alerts: RwLock::new(VecDeque::with_capacity(MAX_ALERTS)),
            alert_tx,
            packet_batch_size,
            geoip: RwLock::new(None),
            blocked_countries: RwLock::new(None),
        }
    }

    pub fn analyze(&self, packet: &PacketInfo) {
        // Check for blocked countries
        if let Some(geoip) = self.geoip.read().as_ref() {
            let ip_str = packet.src_ip.to_string();
            if let Some(country) = geoip.lookup_country(packet.src_ip) {
                if let Some(blocked_set) = self.blocked_countries.read().as_ref() {
                    if blocked_set.read().contains(&country) {
                        let alert = Alert::blocked_country(ip_str.clone(), country);
                        self.process_alert(alert);
                    }
                }
            }
        }

        if packet.protocol == Protocol::Tcp {
            if let Some(dst_port) = packet.dst_port {
                let scan_alert = {
                    let detector = self.port_scan_detector.read();
                    detector.check(&packet.src_ip.to_string(), dst_port, true)
                };

                if let Some(scan_alert) = scan_alert {
                    let alert = Alert::port_scan(scan_alert);
                    self.process_alert(alert);
                }
                
                let bf_alert = {
                    let detector = self.brute_force_detector.write();
                    detector.check(&packet.src_ip.to_string(), dst_port)
                };
                
                if let Some(bf_alert) = bf_alert {
                    let alert = Alert::brute_force(bf_alert);
                    self.process_alert(alert);
                }
            }
        }
    }
    
    fn process_alert(&self, alert: Alert) {
        info!("{}", alert.message);
        let mut alerts = self.recent_alerts.write();
        if alerts.len() >= MAX_ALERTS {
            alerts.pop_front();
        }
        alerts.push_back(alert.clone());
        let _ = self.alert_tx.send(alert);
    }

    /// Batch analyze packets with Rayon parallelization
    pub fn batch_analyze(&self, packets: &[PacketInfo]) -> Vec<Alert> {
        let alerts: Vec<Alert> = packets
            .par_iter()
            .filter_map(|packet| {
                // Check local copy/reference for blocked country
                if let Some(geoip) = self.geoip.read().as_ref() {
                    if let Some(country) = geoip.lookup_country(packet.src_ip) {
                        if let Some(blocked_set) = self.blocked_countries.read().as_ref() {
                            if blocked_set.read().contains(&country) {
                                return Some(Alert::blocked_country(packet.src_ip.to_string(), country));
                            }
                        }
                    }
                }

                if packet.protocol == Protocol::Tcp {
                    if let Some(dst_port) = packet.dst_port {
                        // Check for Port Scans
                        let scan_alert = self.port_scan_detector.read().check(&packet.src_ip.to_string(), dst_port, true);
                        if let Some(scan_alert) = scan_alert {
                            return Some(Alert::port_scan(scan_alert));
                        }

                        // Check for Brute Force
                        let bf_alert = self.brute_force_detector.read().check(&packet.src_ip.to_string(), dst_port);
                        if let Some(bf_alert) = bf_alert {
                            return Some(Alert::brute_force(bf_alert));
                        }
                    }
                }
                None
            })
            .collect();

        // Add alerts to recent alerts and broadcast
        for alert in &alerts {
            self.process_alert(alert.clone());
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
        self.brute_force_detector.write().cleanup();
    }

    pub fn get_recent_alerts(&self) -> Vec<Alert> {
        self.recent_alerts.read().iter().cloned().collect()
    }
}
