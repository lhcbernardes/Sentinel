use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentalConfig {
    pub enabled: bool,
    pub block_adult_domains: bool,
    pub safe_search_engines: bool,
    pub blocked_categories: Vec<String>,
}

impl Default for ParentalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            block_adult_domains: false,
            safe_search_engines: true,
            blocked_categories: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentalStats {
    pub total_blocked: u64,
    pub adult_blocked: u64,
    pub safe_search_triggered: u64,
}

pub struct ParentalControl {
    adult_domains: RwLock<HashSet<String>>,
    safe_search_domains: RwLock<HashSet<String>>,
    config: RwLock<ParentalConfig>,
    stats: RwLock<ParentalStats>,
}

impl ParentalControl {
    pub fn new() -> Self {
        Self {
            adult_domains: RwLock::new(HashSet::new()),
            safe_search_domains: RwLock::new(HashSet::new()),
            config: RwLock::new(ParentalConfig::default()),
            stats: RwLock::new(ParentalStats {
                total_blocked: 0,
                adult_blocked: 0,
                safe_search_triggered: 0,
            }),
        }
    }

    pub fn load_default_lists(&self) {
        // Common adult domain patterns
        let adult_domains = vec![
            "porn", "xxx", "sex", "adult", "18+", "nude", "dating", "webcam", "escort", "strip",
        ];

        let mut domains = self.adult_domains.write();
        for domain in adult_domains {
            domains.insert(domain.to_string());
        }

        // Safe search enforcement domains
        let safe_search = vec![
            "google.com",
            "bing.com",
            "yahoo.com",
            "duckduckgo.com",
            "youtube.com",
            "images.google.com",
            "search.yahoo.com",
        ];

        let mut safe = self.safe_search_domains.write();
        for domain in safe_search {
            safe.insert(domain.to_string());
        }

        tracing::info!(
            "Loaded {} adult patterns, {} safe search domains",
            domains.len(),
            safe.len()
        );
    }

    pub async fn load_online_lists(&self) -> Result<usize, String> {
        let urls = vec![
            "https://raw.githubusercontent.com/nickmilo/Ultimate-Hosts-Blacklist/master/domains/adjio.txt",
            "https://raw.githubusercontent.com/nickmilo/Ultimate-Hosts-Blacklist/master/domains/lifecycle/adjio/active/list.txt",
        ];

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut total_loaded = 0;

        for url in urls {
            match client.get(url).send().await {
                Ok(response) => {
                    if let Ok(content) = response.text().await {
                        let count = self.parse_blocklist(&content);
                        total_loaded += count;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load list from {}: {}", url, e);
                }
            }
        }

        tracing::info!(
            "Loaded {} adult domain patterns from online sources",
            total_loaded
        );
        Ok(total_loaded)
    }

    fn parse_blocklist(&self, content: &str) -> usize {
        let mut domains = self.adult_domains.write();
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

            if !domain.is_empty() {
                domains.insert(domain.to_string());
                count += 1;
            }
        }

        count
    }

    pub fn check_domain(&self, domain: &str) -> ParentalDecision {
        let config = self.config.read();

        if !config.enabled {
            return ParentalDecision::Allowed;
        }

        let domain_lower = domain.to_lowercase();

        // Check adult domains
        if config.block_adult_domains {
            let adult = self.adult_domains.read();
            for blocked in adult.iter() {
                if domain_lower.contains(&blocked.to_lowercase()) {
                    self.stats.write().adult_blocked += 1;
                    self.stats.write().total_blocked += 1;
                    return ParentalDecision::Blocked(Reason::Adult);
                }
            }
        }

        // Check safe search
        if config.safe_search_engines {
            let safe = self.safe_search_domains.read();
            if safe.contains(&domain_lower) || domain_lower.contains("search?") {
                self.stats.write().safe_search_triggered += 1;
                return ParentalDecision::SafeSearchRequired;
            }
        }

        ParentalDecision::Allowed
    }

    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.config.write().enabled = enabled;
    }

    pub fn set_block_adults(&self, enabled: bool) {
        self.config.write().block_adult_domains = enabled;
    }

    pub fn set_safe_search(&self, enabled: bool) {
        self.config.write().safe_search_engines = enabled;
    }

    pub fn update_config(&self, new_config: ParentalConfig) {
        *self.config.write() = new_config;
    }

    pub fn get_config(&self) -> ParentalConfig {
        self.config.read().clone()
    }

    pub fn get_stats(&self) -> ParentalStats {
        self.stats.read().clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentalDecision {
    Allowed,
    Blocked(Reason),
    SafeSearchRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Adult,
    Custom,
}

impl Default for ParentalControl {
    fn default() -> Self {
        Self::new()
    }
}
