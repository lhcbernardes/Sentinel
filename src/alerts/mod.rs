use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub mod rules;

pub use rules::{AlertAction, AlertCondition, AlertContext, AlertRule, AlertRuleEngine};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "INFO"),
            AlertSeverity::Warning => write!(f, "WARNING"),
            AlertSeverity::Error => write!(f, "ERROR"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub notify_new_device: bool,
    pub notify_port_scan: bool,
    pub notify_blocked_domain: bool,
    pub notify_blocked_ip: bool,
    pub notify_critical: bool,
    pub min_severity: AlertSeverity,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            notify_new_device: true,
            notify_port_scan: true,
            notify_blocked_domain: true,
            notify_blocked_ip: true,
            notify_critical: true,
            min_severity: AlertSeverity::Warning,
        }
    }
}

pub struct AlertManager {
    config: RwLock<AlertConfig>,
    telegram_config: RwLock<TelegramConfig>,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(AlertConfig::default()),
            telegram_config: RwLock::new(TelegramConfig::default()),
        }
    }

    pub fn update_config(&self, config: AlertConfig) {
        *self.config.write() = config;
    }

    pub fn get_config(&self) -> AlertConfig {
        self.config.read().clone()
    }

    pub fn configure_telegram(&self, config: TelegramConfig) {
        *self.telegram_config.write() = config;
    }

    pub fn send_alert(&self, title: &str, message: &str, severity: AlertSeverity) {
        tracing::info!("[ALERT {}] {} - {}", severity, title, message);
    }

    pub fn notify_new_device(&self, mac: &str) {
        self.send_alert("New Device", &format!("MAC: {}", mac), AlertSeverity::Info);
    }

    pub fn notify_port_scan(&self, ip: &str, count: usize) {
        self.send_alert(
            "Port Scan",
            &format!("IP: {} ({} ports)", ip, count),
            AlertSeverity::Warning,
        );
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}
