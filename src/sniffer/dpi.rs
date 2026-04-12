use base64::{engine::general_purpose::STANDARD, Engine};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiResult {
    pub application: String,
    pub category: String,
    pub pii_detected: bool,
    pub pii_types: Vec<String>,
    pub sensitive_data: Vec<SensitiveData>,
    pub risk_level: String,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveData {
    pub data_type: String,
    pub value: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DpiStats {
    pub packets_inspected: u64,
    pub applications_detected: HashMap<String, u64>,
    pub pii_detections: u64,
    pub sensitive_data_count: u64,
}

pub struct DpiEngine {
    stats: Arc<RwLock<DpiStats>>,
    rules: Arc<RwLock<Vec<DpiRule>>>,
    email_regex: regex::Regex,
    phone_regex: regex::Regex,
    cpf_regex: regex::Regex,
    credit_card_regex: regex::Regex,
    ssn_regex: regex::Regex,
    password_regex: regex::Regex,
    api_key_regex: regex::Regex,
}

#[derive(Debug, Clone)]
struct DpiRule {
    name: String,
    pattern: String,
    application: String,
    category: String,
}

impl DpiEngine {
    pub fn new() -> Self {
        let rules = vec![
            DpiRule {
                name: "HTTP".to_string(),
                pattern: "HTTP/1".to_string(),
                application: "HTTP".to_string(),
                category: "Web".to_string(),
            },
            DpiRule {
                name: "TLS".to_string(),
                pattern: "\x16\x03".to_string(),
                application: "TLS".to_string(),
                category: "Encrypted".to_string(),
            },
            DpiRule {
                name: "DNS".to_string(),
                pattern: "\x00\x00\x01\x00".to_string(),
                application: "DNS".to_string(),
                category: "DNS".to_string(),
            },
            DpiRule {
                name: "SSH".to_string(),
                pattern: "SSH-".to_string(),
                application: "SSH".to_string(),
                category: "Remote Access".to_string(),
            },
            DpiRule {
                name: "SMTP".to_string(),
                pattern: "220 ".to_string(),
                application: "SMTP".to_string(),
                category: "Email".to_string(),
            },
            DpiRule {
                name: "FTP".to_string(),
                pattern: "220 ".to_string(),
                application: "FTP".to_string(),
                category: "File Transfer".to_string(),
            },
            DpiRule {
                name: "SMB".to_string(),
                pattern: "\u{FF}SMB".to_string(),
                application: "SMB".to_string(),
                category: "File Sharing".to_string(),
            },
            DpiRule {
                name: "RDP".to_string(),
                pattern: "\x03\x00\x00".to_string(),
                application: "RDP".to_string(),
                category: "Remote Access".to_string(),
            },
            DpiRule {
                name: "QUIC".to_string(),
                pattern: "\x00\x00\x00".to_string(),
                application: "QUIC".to_string(),
                category: "Web".to_string(),
            },
        ];

        Self {
            stats: Arc::new(RwLock::new(DpiStats::default())),
            rules: Arc::new(RwLock::new(rules)),
            email_regex: regex::Regex::new(r"[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}").unwrap(),
            phone_regex: regex::Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap(),
            cpf_regex: regex::Regex::new(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b").unwrap(),
            credit_card_regex: regex::Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
                .unwrap(),
            ssn_regex: regex::Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap(),
            password_regex: regex::Regex::new(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+").unwrap(),
            api_key_regex: regex::Regex::new(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*[\w-]{20,}")
                .unwrap(),
        }
    }

    pub fn inspect(&self, data: &str, protocol: &str) -> DpiResult {
        let mut stats = self.stats.write();
        stats.packets_inspected += 1;

        let decoded = STANDARD.decode(data).unwrap_or_default();
        let payload = String::from_utf8_lossy(&decoded);

        let mut application = protocol.to_string();
        let mut category = "Unknown".to_string();
        let mut indicators = Vec::new();

        for rule in self.rules.read().iter() {
            if payload.contains(&rule.pattern) || protocol.eq_ignore_ascii_case(&rule.name) {
                application = rule.application.clone();
                category = rule.category.clone();
                *stats
                    .applications_detected
                    .entry(application.clone())
                    .or_insert(0) += 1;
                indicators.push(format!("Pattern match: {}", rule.name));
                break;
            }
        }

        let (pii_detected, pii_types) = self.detect_pii(&payload);
        if pii_detected {
            stats.pii_detections += 1;
        }

        let sensitive_data = self.detect_sensitive_data(&payload);
        stats.sensitive_data_count += sensitive_data.len() as u64;

        let risk_level = self.assess_risk(pii_detected, &sensitive_data, &category);

        DpiResult {
            application,
            category,
            pii_detected,
            pii_types,
            sensitive_data,
            risk_level,
            indicators,
        }
    }

    fn detect_pii(&self, data: &str) -> (bool, Vec<String>) {
        let mut pii_types = Vec::new();

        if self.email_regex.is_match(data) {
            pii_types.push("Email".to_string());
        }
        if self.phone_regex.is_match(data) {
            pii_types.push("Phone".to_string());
        }
        if self.cpf_regex.is_match(data) {
            pii_types.push("CPF".to_string());
        }

        (!pii_types.is_empty(), pii_types)
    }

    fn detect_sensitive_data(&self, data: &str) -> Vec<SensitiveData> {
        let mut results = Vec::new();

        if let Some(m) = self.credit_card_regex.find(data) {
            results.push(SensitiveData {
                data_type: "Credit Card".to_string(),
                value: format!("****-****-****-{}", &m.as_str()[12..]),
                start: m.start(),
                end: m.end(),
            });
        }

        if let Some(m) = self.ssn_regex.find(data) {
            results.push(SensitiveData {
                data_type: "SSN".to_string(),
                value: format!("***-**-{}", &m.as_str()[m.len() - 4..]),
                start: m.start(),
                end: m.end(),
            });
        }

        if let Some(m) = self.password_regex.find(data) {
            results.push(SensitiveData {
                data_type: "Password".to_string(),
                value: "***".to_string(),
                start: m.start(),
                end: m.end(),
            });
        }

        if let Some(m) = self.api_key_regex.find(data) {
            results.push(SensitiveData {
                data_type: "API Key".to_string(),
                value: "***".to_string(),
                start: m.start(),
                end: m.end(),
            });
        }

        results
    }

    fn assess_risk(
        &self,
        pii_detected: bool,
        sensitive_data: &[SensitiveData],
        category: &str,
    ) -> String {
        let mut score = 0;

        if pii_detected {
            score += 30;
        }
        if !sensitive_data.is_empty() {
            score += 50;
        }
        if category == "Remote Access" || category == "File Transfer" {
            score += 20;
        }
        if category == "Encrypted" {
            score += 10;
        }

        if score >= 70 {
            "high".to_string()
        } else if score >= 30 {
            "medium".to_string()
        } else {
            "low".to_string()
        }
    }

    pub fn get_stats(&self) -> DpiStats {
        self.stats.read().clone()
    }

    pub fn reset_stats(&self) {
        let mut stats = self.stats.write();
        *stats = DpiStats::default();
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pii() {
        let engine = DpiEngine::new();
        let test_data = "user@example.com, phone: 555-123-4567";
        let (detected, types) = engine.detect_pii(test_data);
        assert!(detected);
        assert!(types.contains(&"Email".to_string()));
    }

    #[test]
    fn test_detect_credit_card() {
        let engine = DpiEngine::new();
        let test_data = "Card: 4111-1111-1111-1111";
        let sensitive = engine.detect_sensitive_data(test_data);
        assert!(!sensitive.is_empty());
    }
}
