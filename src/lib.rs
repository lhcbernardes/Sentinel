pub mod alerts;
pub mod anomaly;
pub mod auth;
pub mod backup;
pub mod blocking;
pub mod db;
pub mod devices;
pub mod error;
pub mod history;
pub mod logs;
pub mod metrics;
pub mod network;
pub mod notifications;
pub mod sniffer;
pub mod stats;
pub mod threatintel;
pub mod utils;
pub mod web;

use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::broadcast;

pub use alerts::{AlertConfig, AlertManager, AlertRule, AlertRuleEngine};
pub use anomaly::detector::Alert;
pub use auth::AuthManager;
pub use backup::{BackupConfig, BackupManager, BackupMetadata};
pub use blocking::blocklist::{BlockType, Blocklist, BlocklistConfig};
pub use devices::device::{Device, RiskLevel};
pub use history::{CurrentStats, HistoryManager, TrafficSample};
pub use logs::{LogEntry, LogLevel, LogManager};
pub use metrics::{MetricsExporter, PrometheusServer};
pub use network::{DhcpMonitor, NetworkScanner, VpnManager};
pub use notifications::NotificationManager;
pub use sniffer::dpi::DpiEngine;
pub use sniffer::netflow::NetFlowRecord;
pub use sniffer::packet::PacketInfo;
pub use sniffer::{PacketPool, PooledPacketInfo};
pub use stats::{NetworkStats, StatsManager};
pub use threatintel::ThreatIntelligence;
pub use utils::{LruCache, WorkStealingQueue};

/// Maximum number of packets to keep in the in-memory cache.
const PACKET_CACHE_SIZE: usize = 1000;

#[derive(Clone)]
pub struct AppState {
    pub packet_tx: broadcast::Sender<PacketInfo>,
    pub alert_tx: broadcast::Sender<Alert>,
    pub packet_cache: Arc<RwLock<VecDeque<PacketInfo>>>,
    pub device_manager: Arc<crate::devices::DeviceManager>,
    pub anomaly_detector: Arc<crate::anomaly::AnomalyDetector>,
    pub database: Arc<crate::db::Database>,
    pub blocklist: Arc<crate::blocking::Blocklist>,
    pub dns_sinkhole: Arc<crate::blocking::DnsSinkhole>,
    pub firewall: Arc<crate::blocking::FirewallManager>,
    pub auth: Arc<AuthManager>,
    pub logs: Arc<LogManager>,
    pub alerts: Arc<AlertManager>,
    pub history: Arc<HistoryManager>,
    pub network_scanner: Arc<crate::network::NetworkScanner>,
    pub dhcp_monitor: Arc<DhcpMonitor>,
    pub vpn_manager: Arc<VpnManager>,
    pub stats: Arc<StatsManager>,
    pub backup: Arc<BackupManager>,
    pub netflow_collector: Arc<RwLock<VecDeque<NetFlowRecord>>>,
    pub dpi_engine: Arc<DpiEngine>,
    pub metrics: Arc<MetricsExporter>,
    pub template_cache: Arc<crate::web::routes::TemplateCache>,
    pub parental_control: Arc<crate::blocking::ParentalControl>,
    pub alert_rules: Arc<crate::alerts::AlertRuleEngine>,
    pub notifications: Arc<crate::notifications::NotificationManager>,
    pub threat_intel: Arc<crate::threatintel::ThreatIntelligence>,
    pub ml_detector: Arc<RwLock<crate::anomaly::MlDetector>>,
    pub client_manager: Arc<crate::blocking::ClientManager>,
}

impl AppState {
    pub fn new(
        device_manager: Arc<crate::devices::DeviceManager>,
        anomaly_detector: Arc<crate::anomaly::AnomalyDetector>,
        database: Arc<crate::db::Database>,
        blocklist: Arc<crate::blocking::Blocklist>,
        dns_sinkhole: Arc<crate::blocking::DnsSinkhole>,
        firewall: Arc<crate::blocking::FirewallManager>,
    ) -> Self {
        let (packet_tx, _) = broadcast::channel(10000);
        let (alert_tx, _) = broadcast::channel(1000);

        Self {
            packet_tx,
            alert_tx,
            packet_cache: Arc::new(RwLock::new(VecDeque::with_capacity(PACKET_CACHE_SIZE))),
            device_manager,
            anomaly_detector,
            database,
            blocklist,
            dns_sinkhole,
            firewall,
            auth: Arc::new(AuthManager::new()),
            logs: Arc::new(LogManager::new(10000)),
            alerts: Arc::new(AlertManager::new()),
            history: Arc::new(HistoryManager::new()),
            network_scanner: Arc::new(NetworkScanner::new()),
            dhcp_monitor: Arc::new(DhcpMonitor::new()),
            vpn_manager: Arc::new(VpnManager::new()),
            stats: Arc::new(StatsManager::new()),
            backup: Arc::new(BackupManager::new()),
            netflow_collector: Arc::new(RwLock::new(VecDeque::new())),
            dpi_engine: Arc::new(DpiEngine::new()),
            metrics: Arc::new(MetricsExporter::new()),
            template_cache: Arc::new(crate::web::routes::TemplateCache::new(3600)),
            parental_control: Arc::new(crate::blocking::ParentalControl::new()),
            alert_rules: Arc::new(crate::alerts::AlertRuleEngine::new()),
            notifications: Arc::new(crate::notifications::NotificationManager::new()),
            threat_intel: Arc::new(crate::threatintel::ThreatIntelligence::new()),
            ml_detector: Arc::new(RwLock::new(crate::anomaly::MlDetector::new())),
            client_manager: Arc::new(crate::blocking::ClientManager::new()),
        }
    }

    pub fn add_packet(&self, packet: PacketInfo) {
        let mut cache = self.packet_cache.write();

        while cache.len() >= PACKET_CACHE_SIZE {
            cache.pop_front();
        }
        cache.push_back(packet.clone());

        let _ = self.packet_tx.send(packet);
    }
}

// NOTE: Default is intentionally not implemented for AppState.
// AppState must be constructed via AppState::new() with its required dependencies.
