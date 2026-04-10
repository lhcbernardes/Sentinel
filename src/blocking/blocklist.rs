use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

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

pub struct Blocklist {
    trackers: RwLock<HashSet<String>>,
    malware: RwLock<HashSet<String>>,
    attackers: RwLock<HashSet<String>>,
    custom: RwLock<HashSet<String>>,
    config: RwLock<BlocklistConfig>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self {
            trackers: RwLock::new(HashSet::with_capacity(50_000)),
            malware: RwLock::new(HashSet::with_capacity(50_000)),
            attackers: RwLock::new(HashSet::with_capacity(10_000)),
            custom: RwLock::new(HashSet::with_capacity(1_000)),
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

        let mut trackers = self.trackers.write();
        for domain in default_trackers {
            trackers.insert(domain.to_string());
        }

        let default_malware = vec![
            "malware-domain.com",
            "phishing-site.net",
            "cryptominer.xyz",
            "exploit-kit.org",
        ];

        let mut malware = self.malware.write();
        for domain in default_malware {
            malware.insert(domain.to_string());
        }

        tracing::info!(
            "Loaded default blocklists: {} trackers, {} malware",
            trackers.len(),
            malware.len()
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
                let mut set = self.trackers.write();
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        set.insert(line.to_string());
                    }
                }
                set.len()
            }
            BlockType::Malware => {
                let mut set = self.malware.write();
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        set.insert(line.to_string());
                    }
                }
                set.len()
            }
            BlockType::Attacker => {
                let mut set = self.attackers.write();
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        set.insert(line.to_string());
                    }
                }
                set.len()
            }
            BlockType::Custom => {
                let mut set = self.custom.write();
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        set.insert(line.to_string());
                    }
                }
                set.len()
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
                let mut set = self.trackers.write();
                for domain in domains {
                    set.insert(domain);
                }
                Ok(set.len())
            }
            BlockType::Malware => {
                let mut set = self.malware.write();
                for domain in domains {
                    set.insert(domain);
                }
                Ok(set.len())
            }
            BlockType::Attacker => {
                let mut set = self.attackers.write();
                for domain in domains {
                    set.insert(domain);
                }
                Ok(set.len())
            }
            BlockType::Custom => {
                let mut set = self.custom.write();
                for domain in domains {
                    set.insert(domain);
                }
                Ok(set.len())
            }
        }
    }

    fn parse_blocklist(content: &str) -> Vec<String> {
        let mut domains = Vec::new();

        for line in content.lines() {
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

    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        if self.config.read().block_trackers && self.trackers.read().contains(&domain_lower) {
            return true;
        }

        if self.config.read().block_malware && self.malware.read().contains(&domain_lower) {
            return true;
        }

        if self.config.read().block_attackers && self.attackers.read().contains(&domain_lower) {
            return true;
        }

        if self.custom.read().contains(&domain_lower) {
            return true;
        }

        false
    }

    pub fn add_custom_block(&self, entry: String) {
        let mut set = self.custom.write();
        set.insert(entry);
    }

    pub fn add_attacker(&self, entry: String) {
        let mut set = self.attackers.write();
        set.insert(entry);
    }

    pub fn stats(&self) -> BlocklistStats {
        BlocklistStats {
            trackers: self.trackers.read().len(),
            malware: self.malware.read().len(),
            attackers: self.attackers.read().len(),
            custom: self.custom.read().len(),
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
