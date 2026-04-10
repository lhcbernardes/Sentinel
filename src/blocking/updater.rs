use crate::blocking::blocklist::{BlockType, Blocklist};
use std::sync::Arc;
use std::time::Duration;

const BLACKLIST_URLS_URL: &str =
    "https://raw.githubusercontent.com/fabriziosalmi/blacklists/main/blacklists.fqdn.urls";

pub struct BlocklistUpdater {
    blocklist: Arc<Blocklist>,
}

impl BlocklistUpdater {
    pub fn new(blocklist: Arc<Blocklist>) -> Self {
        Self { blocklist }
    }

    pub async fn update_all(&self) -> Result<(), String> {
        tracing::info!("Starting blocklist update from fabriziosalmi/blacklists...");

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let response = client
            .get(BLACKLIST_URLS_URL)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch URL list: {}", e))?;

        let content = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let urls: Vec<&str> = content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
            .collect();

        tracing::info!("Found {} blocklist URLs to process", urls.len());

        let mut total_trackers = 0;
        let mut total_malware = 0;

        for (i, url) in urls.iter().enumerate() {
            let url = url.trim();

            let block_type = if url.contains("tracker")
                || url.contains("ads")
                || url.contains("Ad")
                || url.contains("privacy")
            {
                BlockType::Tracker
            } else if url.contains("malware")
                || url.contains("phishing")
                || url.contains("scam")
                || url.contains("badware")
                || url.contains("toxic")
            {
                BlockType::Malware
            } else if url.contains("attacker") || url.contains("spam") {
                BlockType::Attacker
            } else {
                BlockType::Tracker
            };

            match self.blocklist.load_from_url(url, block_type).await {
                Ok(count) => {
                    if block_type == BlockType::Tracker {
                        total_trackers += count;
                    } else {
                        total_malware += count;
                    }
                    tracing::info!("[{}] Loaded {} entries from {}", i + 1, count, url);
                }
                Err(e) => {
                    tracing::warn!("[{}] Failed to load {}: {}", i + 1, url, e);
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tracing::info!(
            "Blocklist update complete: {} trackers, {} malware total",
            total_trackers,
            total_malware
        );

        Ok(())
    }

    pub async fn update_trackers(&self) -> Result<usize, String> {
        let trackers = vec![
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts",
            "https://v.firebog.net/hosts/Easylist.txt",
            "https://v.firebog.net/hosts/AdguardDNS.txt",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
            "https://hostfiles.frogeye.fr/firstparty-only-trackers-hosts.txt",
        ];

        let mut total = 0;

        for url in trackers {
            match self.blocklist.load_from_url(url, BlockType::Tracker).await {
                Ok(count) => {
                    total += count;
                    tracing::info!("Loaded {} tracker entries from {}", count, url);
                }
                Err(e) => {
                    tracing::warn!("Failed to load {}: {}", url, e);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok(total)
    }

    pub async fn update_malware(&self) -> Result<usize, String> {
        let malware = vec![
            "https://v.firebog.net/hosts/Prigent-Malware.txt",
            "https://v.firebog.net/hosts/RPiList-Malware.txt",
            "https://v.firebog.net/hosts/RPiList-Phishing.txt",
            "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
            "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt",
        ];

        let mut total = 0;

        for url in malware {
            match self.blocklist.load_from_url(url, BlockType::Malware).await {
                Ok(count) => {
                    total += count;
                    tracing::info!("Loaded {} malware entries from {}", count, url);
                }
                Err(e) => {
                    tracing::warn!("Failed to load {}: {}", url, e);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok(total)
    }

    pub async fn update_attackers(&self) -> Result<usize, String> {
        let attackers = vec![
            "https://phishunt.io/feed.txt",
            "https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt",
        ];

        let mut total = 0;

        for url in attackers {
            match self.blocklist.load_from_url(url, BlockType::Attacker).await {
                Ok(count) => {
                    total += count;
                    tracing::info!("Loaded {} attacker entries from {}", count, url);
                }
                Err(e) => {
                    tracing::warn!("Failed to load {}: {}", url, e);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok(total)
    }
}
