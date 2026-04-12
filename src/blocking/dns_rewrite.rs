use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDnsRecord {
    pub domain: String,
    pub ip: IpAddr,
    pub ttl: u32,
    pub enabled: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRewriteConfig {
    pub enabled: bool,
}

impl Default for DnsRewriteConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

pub struct DnsRewriteManager {
    records: RwLock<HashMap<String, LocalDnsRecord>>,
    config: RwLock<DnsRewriteConfig>,
}

impl DnsRewriteManager {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            config: RwLock::new(DnsRewriteConfig::default()),
        }
    }

    pub fn add_record(&self, domain: String, ip: IpAddr, ttl: u32, enabled: bool, description: Option<String>) {
        let record = LocalDnsRecord {
            domain: domain.clone(),
            ip,
            ttl,
            enabled,
            description,
        };
        self.records.write().insert(domain.to_lowercase(), record);
    }

    pub fn remove_record(&self, domain: &str) -> bool {
        self.records
            .write()
            .remove(&domain.to_lowercase())
            .is_some()
    }

    pub fn lookup(&self, domain: &str) -> Option<IpAddr> {
        self.records
            .read()
            .get(&domain.to_lowercase())
            .filter(|r| r.enabled)
            .map(|r| r.ip)
    }

    pub fn get_record(&self, domain: &str) -> Option<LocalDnsRecord> {
        self.records.read().get(&domain.to_lowercase()).cloned()
    }

    pub fn get_all_records(&self) -> Vec<LocalDnsRecord> {
        self.records.read().values().cloned().collect()
    }

    pub fn clear(&self) {
        self.records.write().clear();
    }

    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.config.write().enabled = enabled;
    }

    pub fn import_records(&self, records: Vec<LocalDnsRecord>) {
        let mut map = self.records.write();
        for record in records {
            map.insert(record.domain.clone(), record);
        }
    }

    pub fn export_records(&self) -> Vec<LocalDnsRecord> {
        self.records.read().values().cloned().collect()
    }
}

impl Default for DnsRewriteManager {
    fn default() -> Self {
        Self::new()
    }
}
