use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigExport {
    pub version: String,
    pub timestamp: i64,
    pub blocklists: BlocklistExport,
    pub client_policies: HashMap<String, ClientPolicyExport>,
    pub dns_rewrites: Vec<DnsRewriteExport>,
    pub parental: Option<ParentalExport>,
    pub alert_rules: Vec<AlertRuleExport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistExport {
    pub trackers: Vec<String>,
    pub malware: Vec<String>,
    pub attackers: Vec<String>,
    pub custom: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPolicyExport {
    pub group: String,
    pub block_trackers: bool,
    pub block_malware: bool,
    pub block_adults: bool,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRewriteExport {
    pub domain: String,
    pub ip: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentalExport {
    pub enabled: bool,
    pub block_adults: bool,
    pub safe_search: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleExport {
    pub name: String,
    pub enabled: bool,
    pub condition: String,
    pub action: String,
}

pub struct ConfigExporter {
    blocklist: Arc<crate::blocking::Blocklist>,
    client_manager: Arc<crate::blocking::ClientManager>,
    dns_rewrite: Arc<crate::blocking::DnsRewriteManager>,
    parental: Arc<crate::blocking::ParentalControl>,
    alert_rules: Arc<crate::alerts::AlertRuleEngine>,
}

impl ConfigExporter {
    pub fn new(
        blocklist: Arc<crate::blocking::Blocklist>,
        client_manager: Arc<crate::blocking::ClientManager>,
        dns_rewrite: Arc<crate::blocking::DnsRewriteManager>,
        parental: Arc<crate::blocking::ParentalControl>,
        alert_rules: Arc<crate::alerts::AlertRuleEngine>,
    ) -> Self {
        Self {
            blocklist,
            client_manager,
            dns_rewrite,
            parental,
            alert_rules,
        }
    }

    pub fn export(&self) -> ConfigExport {
        let stats = self.blocklist.stats();

        // Export blocklists (just counts for now - full export would be huge)
        let blocklists = BlocklistExport {
            trackers: vec![],
            malware: vec![],
            attackers: vec![],
            custom: self
                .blocklist
                .stats()
                .custom
                .to_string()
                .split(',')
                .map(String::from)
                .collect(),
        };

        // Export client policies
        let mut client_policies = HashMap::new();
        for client in self.client_manager.get_all_clients() {
            client_policies.insert(
                client.client_id.clone(),
                ClientPolicyExport {
                    group: format!("{:?}", client.group),
                    block_trackers: client.block_trackers,
                    block_malware: client.block_malware,
                    block_adults: client.block_adults,
                    allowed_domains: client.allowed_domains,
                    blocked_domains: client.blocked_domains,
                },
            );
        }

        // Export DNS rewrites
        let dns_rewrites = self
            .dns_rewrite
            .get_all_records()
            .into_iter()
            .map(|r| DnsRewriteExport {
                domain: r.domain,
                ip: r.ip.to_string(),
                ttl: r.ttl,
            })
            .collect();

        // Export parental
        let parental_config = self.parental.get_config();
        let parental = Some(ParentalExport {
            enabled: parental_config.enabled,
            block_adults: parental_config.block_adult_domains,
            safe_search: parental_config.safe_search_engines,
        });

        // Export alert rules
        let alert_rules = self
            .alert_rules
            .get_rules()
            .into_iter()
            .map(|r| AlertRuleExport {
                name: r.name,
                enabled: r.enabled,
                condition: format!("{:?}", r.condition),
                action: format!("{:?}", r.action),
            })
            .collect();

        ConfigExport {
            version: "1.0.0".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            blocklists,
            client_policies,
            dns_rewrites,
            parental,
            alert_rules,
        }
    }

    pub fn export_to_json(&self) -> Result<String, String> {
        let config = self.export();
        serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize config: {}", e))
    }

    pub fn import(&self, json: &str) -> Result<(), String> {
        let config: ConfigExport =
            serde_json::from_str(json).map_err(|e| format!("Failed to parse config: {}", e))?;

        // Import custom blocklist entries
        for domain in config.blocklists.custom {
            self.blocklist.add_custom_block(domain);
        }

        // Import DNS rewrites
        for rewrite in config.dns_rewrites {
            if let Ok(ip) = rewrite.ip.parse() {
                self.dns_rewrite
                    .add_record(rewrite.domain, ip, rewrite.ttl, None);
            }
        }

        // Import parental config
        if let Some(p) = config.parental {
            self.parental.set_enabled(p.enabled);
            self.parental.set_block_adults(p.block_adults);
            self.parental.set_safe_search(p.safe_search);
        }

        tracing::info!("Configuration imported successfully");
        Ok(())
    }
}
