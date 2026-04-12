use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;
use ahash::RandomState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockType {
    Tracker,
    Malware,
    Attacker,
    Custom,
}

impl std::fmt::Display for BlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockType::Tracker => write!(f, "tracker"),
            BlockType::Malware => write!(f, "malware"),
            BlockType::Attacker => write!(f, "attacker"),
            BlockType::Custom => write!(f, "custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistConfig {
    pub enabled: bool,
    pub block_trackers: bool,
    pub block_malware: bool,
    pub block_attackers: bool,
    pub auto_block_attackers: bool,
    pub port_scan_threshold: u32,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_trackers: true,
            block_malware: true,
            block_attackers: true,
            auto_block_attackers: true,
            port_scan_threshold: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistStats {
    pub trackers: usize,
    pub malware: usize,
    pub attackers: usize,
    pub custom: usize,
    pub config: BlocklistConfig,
}

type AHashSet<T> = HashSet<T, RandomState>;

struct BlocklistSets {
    trackers: AHashSet<String>,
    malware: AHashSet<String>,
    attackers: AHashSet<String>,
    custom: AHashSet<String>,
}

impl BlocklistSets {
    fn new() -> Self {
        let hasher = RandomState::new();
        Self {
            trackers: HashSet::with_capacity_and_hasher(50_000, hasher.clone()),
            malware: HashSet::with_capacity_and_hasher(50_000, hasher.clone()),
            attackers: HashSet::with_capacity_and_hasher(10_000, hasher.clone()),
            custom: HashSet::with_capacity_and_hasher(1_000, hasher),
        }
    }
}

pub struct Blocklist {
    sets: RwLock<BlocklistSets>,
    config: RwLock<BlocklistConfig>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self {
            sets: RwLock::new(BlocklistSets::new()),
            config: RwLock::new(BlocklistConfig::default()),
        }
    }

    pub fn load_default_lists(&self) {
        let default_trackers = vec![
            "google-analytics.com",
            "googletagmanager.com",
            "facebook.net",
            "doubleclick.net",
            "adservice.google.com",
            "pagead2.googlesyndication.com",
            "ads.facebook.com",
            "pixel.facebook.com",
            "connect.facebook.net",
            "analytics.twitter.com",
            "ads.twitter.com",
            "bat.bing.com",
            "ads.linkedin.com",
            "pixel.adsafeprotected.com",
            "sb.scorecardresearch.com",
            "quantserve.com",
            "adnxs.com",
            "rubiconproject.com",
            "pubmatic.com",
            "openx.net",
            "casalemedia.com",
            "taboola.com",
            "outbrain.com",
            "criteo.com",
            "amazon-adsystem.com",
        ];

        let mut sets = self.sets.write();
        for domain in default_trackers {
            sets.trackers.insert(domain.to_string());
        }

        let default_malware = vec![
            "malware-domain.com",
            "phishing-site.net",
            "cryptominer.xyz",
            "exploit-kit.org",
        ];

        for domain in default_malware {
            sets.malware.insert(domain.to_string());
        }

        tracing::info!(
            "Loaded default blocklists: {} trackers, {} malware",
            sets.trackers.len(),
            sets.malware.len()
        );
    }

    pub fn load_from_file(&self, path: &Path, block_type: BlockType) -> Result<usize, String> {
        if !path.exists() {
            return Err(format!("Blocklist file not found: {:?}", path));
        }

        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read blocklist: {}", e))?;

        let count = match block_type {
            BlockType::Tracker => {
                let mut sets = self.sets.write();
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        sets.trackers.insert(line.to_string());
                    }
                }
                sets.trackers.len()
            }
            BlockType::Malware => {
                let mut sets = self.sets.write();
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        sets.malware.insert(line.to_string());
                    }
                }
                sets.malware.len()
            }
            BlockType::Attacker => {
                let mut sets = self.sets.write();
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        sets.attackers.insert(line.to_string());
                    }
                }
                sets.attackers.len()
            }
            BlockType::Custom => {
                let mut sets = self.sets.write();
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        sets.custom.insert(line.to_string());
                    }
                }
                sets.custom.len()
            }
        };

        tracing::info!("Loaded {} {} entries from {:?}", count, block_type, path);
        Ok(count)
    }

    /// Maximum allowed blocklist download size (50 MB).
    const MAX_BLOCKLIST_DOWNLOAD_BYTES: u64 = 50 * 1024 * 1024;

    pub async fn load_from_url(&self, url: &str, block_type: BlockType) -> Result<usize, String> {
        // Validate URL to prevent SSRF attacks
        let parsed_url = url::Url::parse(url).map_err(|_| "Invalid URL format".to_string())?;

        // Only allow HTTP and HTTPS
        if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
            return Err("Only HTTP and HTTPS URLs are allowed".to_string());
        }

        // Block private/internal IPs — comprehensive check
        let host = parsed_url.host_str().ok_or("Invalid URL: no host")?;

        if Self::is_private_host(host) {
            return Err("Private/internal URLs are not allowed".to_string());
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch blocklist: {}", e))?;

        // Check Content-Length before downloading to prevent OOM
        if let Some(content_length) = response.content_length() {
            if content_length > Self::MAX_BLOCKLIST_DOWNLOAD_BYTES {
                return Err(format!(
                    "Blocklist too large: {} bytes (max {} MB)",
                    content_length,
                    Self::MAX_BLOCKLIST_DOWNLOAD_BYTES / (1024 * 1024)
                ));
            }
        }

        let content = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        // Also check actual downloaded size
        if content.len() as u64 > Self::MAX_BLOCKLIST_DOWNLOAD_BYTES {
            return Err("Blocklist response body exceeds maximum allowed size".to_string());
        }

        let domains = Self::parse_blocklist(&content);

        match block_type {
            BlockType::Tracker => {
                let mut sets = self.sets.write();
                for domain in domains {
                    sets.trackers.insert(domain);
                }
                Ok(sets.trackers.len())
            }
            BlockType::Malware => {
                let mut sets = self.sets.write();
                for domain in domains {
                    sets.malware.insert(domain);
                }
                Ok(sets.malware.len())
            }
            BlockType::Attacker => {
                let mut sets = self.sets.write();
                for domain in domains {
                    sets.attackers.insert(domain);
                }
                Ok(sets.attackers.len())
            }
            BlockType::Custom => {
                let mut sets = self.sets.write();
                for domain in domains {
                    sets.custom.insert(domain);
                }
                Ok(sets.custom.len())
            }
        }
    }

    fn parse_blocklist(content: &str) -> Vec<String> {
        let lines: Vec<&str> = content.lines().collect();
        let count = lines.len();
        
        // Use parallel processing for large blocklists (>10k lines)
        if count > 10_000 {
            use rayon::prelude::*;
            
            lines.par_iter()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        return None;
                    }

                    let domain = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
                        line.split_whitespace().nth(1).unwrap_or(line)
                    } else if line.contains('/') {
                        line.split('/').next().unwrap_or(line)
                    } else {
                        line
                    };

                    let domain = domain.trim();
                    if !domain.is_empty() && domain.contains('.') {
                        Some(domain.to_lowercase())
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            // Sequential processing for smaller blocklists
            let mut domains = Vec::new();
            for line in lines {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                let domain = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
                    line.split_whitespace().nth(1).unwrap_or(line)
                } else if line.contains('/') {
                    line.split('/').next().unwrap_or(line)
                } else {
                    line
                };

                let domain = domain.trim();
                if !domain.is_empty() && domain.contains('.') {
                    domains.push(domain.to_lowercase());
                }
            }
            domains
        }
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = if domain.bytes().all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'-') {
            domain.to_string()
        } else {
            domain.to_lowercase()
        };

        let sets = self.sets.read();
        let config = self.config.read();
        
        // Single lock acquisition for all checks
        if config.block_trackers && sets.trackers.contains(&domain_lower) {
            return true;
        }

        if config.block_malware && sets.malware.contains(&domain_lower) {
            return true;
        }

        if config.block_attackers && sets.attackers.contains(&domain_lower) {
            return true;
        }

        if sets.custom.contains(&domain_lower) {
            return true;
        }

        false
    }

    pub fn add_custom_block(&self, entry: String) {
        let mut sets = self.sets.write();
        sets.custom.insert(entry);
    }

    pub fn add_attacker(&self, entry: String) {
        let mut sets = self.sets.write();
        sets.attackers.insert(entry);
    }

    pub fn stats(&self) -> BlocklistStats {
        let sets = self.sets.read();
        BlocklistStats {
            trackers: sets.trackers.len(),
            malware: sets.malware.len(),
            attackers: sets.attackers.len(),
            custom: sets.custom.len(),
            config: self.config.read().clone(),
        }
    }

    pub fn get_config(&self) -> BlocklistConfig {
        self.config.read().clone()
    }

    pub fn update_config(&self, config: BlocklistConfig) {
        *self.config.write() = config;
    }
}

impl Blocklist {
    /// Check if a hostname resolves to or represents a private/internal address.
    /// Covers IPv4 private ranges, IPv6 private ranges, localhost, and local domains.
    fn is_private_host(host: &str) -> bool {
        use std::net::IpAddr;

        // Check well-known private hostnames
        if host == "localhost"
            || host == "[::1]"
            || host.ends_with(".local")
            || host.ends_with(".internal")
            || host.ends_with(".localhost")
        {
            return true;
        }

        // Try to parse as IP address for comprehensive range checking
        let ip = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>();

        if let Ok(addr) = ip {
            return match addr {
                IpAddr::V4(v4) => {
                    v4.is_loopback()           // 127.0.0.0/8
                        || v4.is_private()     // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                        || v4.is_link_local()  // 169.254.0.0/16
                        || v4.is_unspecified() // 0.0.0.0
                }
                IpAddr::V6(v6) => {
                    v6.is_loopback()  // ::1
                        || v6.is_unspecified()  // ::
                        // fc00::/7 — Unique Local Addresses
                        || (v6.segments()[0] & 0xfe00) == 0xfc00
                        // fe80::/10 — Link-Local
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                }
            };
        }

        false
    }
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}
