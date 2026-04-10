use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

#[allow(dead_code)]
const ABUSEIPDB_API: &str = "https://api.abuseipdb.com/api/v2/check";
const URLHAUS_URL: &str = "https://urlhaus.abuse.ch/downloads/hostfile/";
const EMERGING_THREATS_URL: &str = "https://v.firebog.net/hosts/Prigent-Malware.txt";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatConfig {
    pub enabled: bool,
    pub update_interval_hours: u32,
    pub check_on_query: bool,
    pub abuseipdb_api_key: Option<String>,
}

impl Default for ThreatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            update_interval_hours: 6,
            check_on_query: false,
            abuseipdb_api_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub indicator: String,
    pub threat_type: ThreatType,
    pub source: String,
    pub confidence: u8,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Phishing,
    Scanner,
    Botnet,
    Spam,
    Proxy,
    VPN,
    Suspicious,
}

impl ThreatEntry {
    pub fn is_malicious(&self) -> bool {
        matches!(
            self.threat_type,
            ThreatType::Malware | ThreatType::Phishing | ThreatType::Botnet
        )
    }
}

pub struct ThreatIntelligence {
    blocked_ips: RwLock<HashSet<String>>,
    blocked_domains: RwLock<HashSet<String>>,
    suspicious_ips: RwLock<HashSet<String>>,
    last_update: RwLock<i64>,
    config: RwLock<ThreatConfig>,
}

impl ThreatIntelligence {
    pub fn new() -> Self {
        Self {
            blocked_ips: RwLock::new(HashSet::new()),
            blocked_domains: RwLock::new(HashSet::new()),
            suspicious_ips: RwLock::new(HashSet::new()),
            last_update: RwLock::new(0),
            config: RwLock::new(ThreatConfig::default()),
        }
    }

    pub async fn update_all(&self) -> Result<(), String> {
        self.update_urlhaus().await?;
        self.update_emerging_threats().await?;

        *self.last_update.write() = chrono::Utc::now().timestamp();
        tracing::info!("Threat intelligence updated");
        Ok(())
    }

    pub async fn update_urlhaus(&self) -> Result<usize, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("Failed to create client: {}", e))?;

        let response = client
            .get(URLHAUS_URL)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch URLhaus: {}", e))?;

        let content = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let count = self.parse_blocklist(&content, ThreatType::Malware);

        tracing::info!("Loaded {} malicious domains from URLhaus", count);
        Ok(count)
    }

    pub async fn update_emerging_threats(&self) -> Result<usize, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("Failed to create client: {}", e))?;

        let response = client
            .get(EMERGING_THREATS_URL)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch Emerging Threats: {}", e))?;

        let content = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let count = self.parse_blocklist(&content, ThreatType::Malware);

        tracing::info!("Loaded {} malicious domains from Emerging Threats", count);
        Ok(count)
    }

    fn parse_blocklist(&self, content: &str, _threat_type: ThreatType) -> usize {
        let mut domains = self.blocked_domains.write();
        let mut count = 0;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let domain = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
                line.split_whitespace().nth(1).unwrap_or(line)
            } else {
                line
            };

            if !domain.is_empty() && domain.contains('.') {
                domains.insert(domain.to_string());
                count += 1;
            }
        }

        count
    }

    pub fn check_ip(&self, ip: &str) -> Option<ThreatEntry> {
        let blocked = self.blocked_ips.read();
        if blocked.contains(ip) {
            return Some(ThreatEntry {
                indicator: ip.to_string(),
                threat_type: ThreatType::Scanner,
                source: "Blocklist".to_string(),
                confidence: 80,
                last_seen: chrono::Utc::now().timestamp(),
            });
        }

        let suspicious = self.suspicious_ips.read();
        if suspicious.contains(ip) {
            return Some(ThreatEntry {
                indicator: ip.to_string(),
                threat_type: ThreatType::Suspicious,
                source: "Blocklist".to_string(),
                confidence: 50,
                last_seen: chrono::Utc::now().timestamp(),
            });
        }

        None
    }

    pub fn check_domain(&self, domain: &str) -> Option<ThreatEntry> {
        let blocked = self.blocked_domains.read();

        let domain_lower = domain.to_lowercase();
        for blocked_domain in blocked.iter() {
            if domain_lower.ends_with(blocked_domain) || domain_lower.contains(blocked_domain) {
                return Some(ThreatEntry {
                    indicator: domain.to_string(),
                    threat_type: ThreatType::Malware,
                    source: "Blocklist".to_string(),
                    confidence: 90,
                    last_seen: chrono::Utc::now().timestamp(),
                });
            }
        }

        None
    }

    pub fn add_blocked_ip(&self, ip: String) {
        self.blocked_ips.write().insert(ip);
    }

    pub fn add_blocked_domain(&self, domain: String) {
        self.blocked_domains.write().insert(domain);
    }

    pub fn get_stats(&self) -> ThreatStats {
        ThreatStats {
            blocked_ips: self.blocked_ips.read().len(),
            blocked_domains: self.blocked_domains.read().len(),
            suspicious_ips: self.suspicious_ips.read().len(),
            last_update: *self.last_update.read(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.config.write().enabled = enabled;
    }

    pub fn set_api_key(&self, key: String) {
        self.config.write().abuseipdb_api_key = Some(key);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStats {
    pub blocked_ips: usize,
    pub blocked_domains: usize,
    pub suspicious_ips: usize,
    pub last_update: i64,
}

impl Default for ThreatIntelligence {
    fn default() -> Self {
        Self::new()
    }
}
