use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const MAX_LOGS: usize = 10000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warning => write!(f, "WARNING"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: i64,
    pub level: LogLevel,
    pub category: String,
    pub message: String,
    pub source_ip: Option<String>,
    pub target_ip: Option<String>,
    pub mac_address: Option<String>,
    pub details: Option<serde_json::Value>,
}

impl LogEntry {
    pub fn new(level: LogLevel, category: &str, message: &str) -> Self {
        Self {
            id: format!("log-{}", Utc::now().timestamp_millis()),
            timestamp: Utc::now().timestamp_millis(),
            level,
            category: category.to_string(),
            message: message.to_string(),
            source_ip: None,
            target_ip: None,
            mac_address: None,
            details: None,
        }
    }

    pub fn with_source_ip(mut self, ip: &str) -> Self {
        self.source_ip = Some(ip.to_string());
        self
    }

    pub fn with_target_ip(mut self, ip: &str) -> Self {
        self.target_ip = Some(ip.to_string());
        self
    }

    pub fn with_mac(self, mac: &str) -> Self {
        self.with_source_ip(mac)
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

pub struct LogManager {
    logs: RwLock<VecDeque<LogEntry>>,
    max_size: usize,
}

impl LogManager {
    pub fn new(max_size: usize) -> Self {
        Self {
            logs: RwLock::new(VecDeque::with_capacity(max_size)),
            max_size,
        }
    }

    pub fn log(&self, entry: LogEntry) {
        let mut logs = self.logs.write();

        if logs.len() >= self.max_size {
            logs.pop_front();
        }

        logs.push_back(entry);
    }

    pub fn debug(&self, category: &str, message: &str) {
        self.log(LogEntry::new(LogLevel::Debug, category, message));
    }

    pub fn info(&self, category: &str, message: &str) {
        self.log(LogEntry::new(LogLevel::Info, category, message));
    }

    pub fn warning(&self, category: &str, message: &str) {
        self.log(LogEntry::new(LogLevel::Warning, category, message));
    }

    pub fn error(&self, category: &str, message: &str) {
        self.log(LogEntry::new(LogLevel::Error, category, message));
    }

    pub fn critical(&self, category: &str, message: &str) {
        self.log(LogEntry::new(LogLevel::Critical, category, message));
    }

    pub fn get_logs(
        &self,
        limit: usize,
        level: Option<LogLevel>,
        category: Option<&str>,
    ) -> Vec<LogEntry> {
        let logs = self.logs.read();

        logs.iter()
            .rev()
            .filter(|l| {
                if let Some(ref lvl) = level {
                    if &l.level != lvl {
                        return false;
                    }
                }
                if let Some(ref cat) = category {
                    if &l.category != cat {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn get_stats(&self) -> LogStats {
        let logs = self.logs.read();

        let mut by_level: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut by_category: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for log in logs.iter() {
            *by_level.entry(format!("{:?}", log.level)).or_insert(0) += 1;
            *by_category.entry(log.category.clone()).or_insert(0) += 1;
        }

        LogStats {
            total: logs.len(),
            by_level,
            by_category,
        }
    }

    pub fn clear(&self) {
        self.logs.write().clear();
    }

    pub fn export(&self) -> Vec<LogEntry> {
        self.logs.read().iter().cloned().collect()
    }

    pub fn get_recent(&self, limit: usize) -> Vec<LogEntry> {
        self.logs.read().iter().rev().take(limit).cloned().collect()
    }
}

impl Default for LogManager {
    fn default() -> Self {
        Self::new(MAX_LOGS)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStats {
    pub total: usize,
    pub by_level: std::collections::HashMap<String, usize>,
    pub by_category: std::collections::HashMap<String, usize>,
}
