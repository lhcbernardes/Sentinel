use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;

use crate::blocking::Blocklist;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateConfig {
    pub enabled: bool,
    pub interval_hours: u32,
    pub sources: Vec<BlocklistSource>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlocklistSource {
    pub name: String,
    pub url: String,
    pub block_type: String,
    pub enabled: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 24,
            sources: vec![
                BlocklistSource {
                    name: "StevenBlack".to_string(),
                    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
                        .to_string(),
                    block_type: "tracker".to_string(),
                    enabled: true,
                },
                BlocklistSource {
                    name: "AdAway".to_string(),
                    url:
                        "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt"
                            .to_string(),
                    block_type: "tracker".to_string(),
                    enabled: true,
                },
                BlocklistSource {
                    name: "Malware Domain List".to_string(),
                    url: "http://www.malwaredomainlist.com/hostslist/hosts.txt".to_string(),
                    block_type: "malware".to_string(),
                    enabled: true,
                },
            ],
        }
    }
}

pub struct BlocklistUpdater {
    config: RwLock<UpdateConfig>,
    blocklist: Arc<Blocklist>,
    last_update: RwLock<Option<i64>>,
    update_in_progress: RwLock<bool>,
}

impl BlocklistUpdater {
    pub fn new(blocklist: Arc<Blocklist>) -> Self {
        Self {
            config: RwLock::new(UpdateConfig::default()),
            blocklist,
            last_update: RwLock::new(None),
            update_in_progress: RwLock::new(false),
        }
    }

    pub fn configure(&self, config: UpdateConfig) {
        *self.config.write() = config;
    }

    pub fn get_config(&self) -> UpdateConfig {
        self.config.read().clone()
    }

    pub fn should_update(&self) -> bool {
        let config = self.config.read();

        if !config.enabled {
            return false;
        }

        if *self.update_in_progress.read() {
            return false;
        }

        if let Some(last) = *self.last_update.read() {
            let hours_since = (chrono::Utc::now().timestamp() - last) / 3600;
            return hours_since >= config.interval_hours as i64;
        }

        true
    }

    pub fn update_now(&self) -> Result<UpdateResult, String> {
        if *self.update_in_progress.read() {
            return Err("Update already in progress".to_string());
        }

        *self.update_in_progress.write() = true;

        let result = self.do_update();

        *self.update_in_progress.write() = false;

        result
    }

    fn do_update(&self) -> Result<UpdateResult, String> {
        let config = self.config.read().clone();
        let mut added = 0;
        let mut failed = 0;

        for source in &config.sources {
            if !source.enabled {
                continue;
            }

            match self.fetch_and_parse(&source.url) {
                Ok(domains) => {
                    for domain in domains {
                        let block_type = match source.block_type.as_str() {
                            "tracker" => crate::blocking::BlockType::Tracker,
                            "malware" => crate::blocking::BlockType::Malware,
                            _ => crate::blocking::BlockType::Custom,
                        };

                        // This would add to blocklist - simplified for now
                        added += 1;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch {}: {}", source.name, e);
                    failed += 1;
                }
            }
        }

        *self.last_update.write() = Some(chrono::Utc::now().timestamp());

        Ok(UpdateResult {
            added,
            failed,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    fn fetch_and_parse(&self, url: &str) -> Result<Vec<String>, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;

        let response = client.get(url).send().map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()));
        }

        let body = response.text().map_err(|e| e.to_string())?;

        let domains: Vec<String> = body
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty() && !line.starts_with('#')
            })
            .filter_map(|line| {
                // Parse hosts file format: "0.0.0.0 domain.com"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[0] == "0.0.0.0" {
                    Some(parts[1].to_string())
                } else {
                    None
                }
            })
            .collect();

        Ok(domains)
    }

    pub fn get_last_update_time(&self) -> Option<i64> {
        *self.last_update.read()
    }

    pub fn is_updating(&self) -> bool {
        *self.update_in_progress.read()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateResult {
    pub added: usize,
    pub failed: usize,
    pub timestamp: i64,
}
