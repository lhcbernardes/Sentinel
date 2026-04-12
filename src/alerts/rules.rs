use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertCondition {
    Threshold {
        metric: String,
        value: f64,
        operator: ComparisonOp,
    },
    Pattern {
        regex: String,
        field: String,
    },
    Anomaly {
        score: f64,
        device_id: Option<String>,
    },
    DnsBlocked {
        domain_pattern: String,
    },
    PortScan {
        source_ip: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for AlertSeverity {
    fn default() -> Self {
        Self::Medium
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOp {
    GreaterThan,
    LessThan,
    Equals,
    NotEquals,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NotificationChannel {
    Telegram { chat_id: String, bot_token: String },
    Email { to: String },
    Slack { webhook_url: String },
    Webhook { url: String },
}

impl Default for NotificationChannel {
    fn default() -> Self {
        Self::Webhook { url: String::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertAction {
    Log,
    Notify {
        channels: Vec<NotificationChannel>,
    },
    Block {
        target: String,
        duration_seconds: Option<u32>,
    },
    Webhook {
        url: String,
        method: HttpMethod,
    },
    Script {
        path: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub condition: AlertCondition,
    pub action: AlertAction,
    pub severity: AlertSeverity,
    pub cooldown_seconds: u32,
    pub last_triggered: Option<i64>,
}

impl AlertRule {
    pub fn new(name: String, condition: AlertCondition, action: AlertAction, severity: AlertSeverity) -> Self {
        Self {
            id: format!("rule-{}", chrono::Utc::now().timestamp_millis()),
            name,
            description: None,
            enabled: true,
            condition,
            action,
            severity,
            cooldown_seconds: 300,
            last_triggered: None,
        }
    }

    pub fn can_trigger(&self) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(last) = self.last_triggered {
            let now = chrono::Utc::now().timestamp();
            return now - last >= self.cooldown_seconds as i64;
        }

        true
    }
}

pub struct AlertRuleEngine {
    rules: RwLock<Vec<AlertRule>>,
    triggered_count: RwLock<HashMap<String, u32>>,
}

impl AlertRuleEngine {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            triggered_count: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_rule(&self, rule: AlertRule) {
        self.rules.write().push(rule);
    }

    pub fn remove_rule(&self, id: &str) -> bool {
        let mut rules = self.rules.write();
        let len_before = rules.len();
        rules.retain(|r| r.id != id);
        rules.len() < len_before
    }

    pub fn get_rules(&self) -> Vec<AlertRule> {
        self.rules.read().clone()
    }

    pub fn set_rule_enabled(&self, id: &str, enabled: bool) -> bool {
        let mut rules = self.rules.write();
        if let Some(rule) = rules.iter_mut().find(|r| r.id == id) {
            rule.enabled = enabled;
            return true;
        }
        false
    }

    pub fn check_condition(&self, condition: &AlertCondition, context: &AlertContext) -> bool {
        match condition {
            AlertCondition::Threshold {
                metric,
                value,
                operator,
            } => {
                let current = context.metrics.get(metric).copied().unwrap_or(0.0);
                match operator {
                    ComparisonOp::GreaterThan => current > *value,
                    ComparisonOp::LessThan => current < *value,
                    ComparisonOp::Equals => (current - value).abs() < 0.001,
                    ComparisonOp::NotEquals => (current - value).abs() >= 0.001,
                }
            }
            AlertCondition::Pattern { regex, field } => {
                let value = context.get_field(field);
                if let Some(v) = value {
                    regex::Regex::new(regex)
                        .map(|r| r.is_match(v))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            AlertCondition::Anomaly { score, device_id } => {
                if let Some(did) = device_id {
                    if context.device_id.as_ref() != Some(did) {
                        return false;
                    }
                }
                context.anomaly_score >= *score
            }
            AlertCondition::DnsBlocked { domain_pattern } => {
                context.dns_blocked
                    && context
                        .domain
                        .as_ref()
                        .map(|d| d.contains(domain_pattern))
                        .unwrap_or(false)
            }
            AlertCondition::PortScan { source_ip } => {
                context.port_scan_detected
                    && context
                        .source_ip
                        .as_ref()
                        .map(|ip| ip == source_ip || source_ip == "*")
                        .unwrap_or(false)
            }
        }
    }

    pub fn evaluate(&self, context: &AlertContext) -> Vec<(AlertRule, AlertAction)> {
        let mut results = Vec::new();
        let rules = self.rules.read().clone();

        for rule in rules {
            if !rule.can_trigger() {
                continue;
            }

            if self.check_condition(&rule.condition, context) {
                results.push((rule.clone(), rule.action.clone()));

                // Update last triggered
                if let Some(r) = self.rules.write().iter_mut().find(|r| r.id == rule.id) {
                    r.last_triggered = Some(chrono::Utc::now().timestamp());
                }

                // Increment count
                *self
                    .triggered_count
                    .write()
                    .entry(rule.id.clone())
                    .or_insert(0) += 1;
            }
        }

        results
    }

    pub fn get_stats(&self) -> HashMap<String, u32> {
        self.triggered_count.read().clone()
    }
}

#[derive(Debug, Clone, Default)]
pub struct AlertContext {
    pub device_id: Option<String>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub domain: Option<String>,
    pub anomaly_score: f64,
    pub port_scan_detected: bool,
    pub dns_blocked: bool,
    pub metrics: HashMap<String, f64>,
}

impl AlertContext {
    pub fn new() -> Self {
        Self {
            device_id: None,
            source_ip: None,
            dest_ip: None,
            domain: None,
            anomaly_score: 0.0,
            port_scan_detected: false,
            dns_blocked: false,
            metrics: HashMap::new(),
        }
    }

    pub fn get_field(&self, field: &str) -> Option<&str> {
        match field {
            "source_ip" => self.source_ip.as_deref(),
            "dest_ip" => self.dest_ip.as_deref(),
            "domain" => self.domain.as_deref(),
            _ => None,
        }
    }
}

impl Default for AlertRuleEngine {
    fn default() -> Self {
        Self::new()
    }
}
