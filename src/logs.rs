use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const DEFAULT_MAX_LOGS: usize = 10000;

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
            LogLevel::Warning => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: i64,
    pub level: LogLevel,
    pub message: String,
    pub source: Option<String>,
}

impl LogEntry {
    pub fn new(level: LogLevel, message: String, source: Option<String>) -> Self {
        Self {
            timestamp: Utc::now().timestamp_millis(),
            level,
            message,
            source,
        }
    }

    pub fn debug(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Debug, message.into(), None)
    }

    pub fn info(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Info, message.into(), None)
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Warning, message.into(), None)
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Error, message.into(), None)
    }

    pub fn critical(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Critical, message.into(), None)
    }
}

pub struct LogManager {
    logs: RwLock<VecDeque<LogEntry>>,
    max_logs: usize,
}

impl LogManager {
    pub fn new(max_logs: usize) -> Self {
        Self {
            logs: RwLock::new(VecDeque::with_capacity(max_logs)),
            max_logs,
        }
    }

    pub fn add(&self, entry: LogEntry) {
        let mut logs = self.logs.write();
        if logs.len() >= self.max_logs {
            logs.pop_front();
        }
        logs.push_back(entry);
    }

    pub fn debug(&self, message: impl Into<String>) {
        self.add(LogEntry::debug(message));
    }

    pub fn info(&self, message: impl Into<String>) {
        self.add(LogEntry::info(message));
    }

    pub fn warning(&self, message: impl Into<String>) {
        self.add(LogEntry::warning(message));
    }

    pub fn error(&self, message: impl Into<String>) {
        self.add(LogEntry::error(message));
    }

    pub fn critical(&self, message: impl Into<String>) {
        self.add(LogEntry::critical(message));
    }

    pub fn get_all(&self) -> Vec<LogEntry> {
        self.logs.read().iter().cloned().collect()
    }

    pub fn get_recent(&self, count: usize) -> Vec<LogEntry> {
        self.logs.read().iter().rev().take(count).cloned().collect()
    }

    pub fn get_by_level(&self, level: LogLevel) -> Vec<LogEntry> {
        self.logs
            .read()
            .iter()
            .filter(|e| e.level == level)
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        self.logs.write().clear();
    }

    pub fn len(&self) -> usize {
        self.logs.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.logs.read().is_empty()
    }
}

impl Default for LogManager {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_LOGS)
    }
}
