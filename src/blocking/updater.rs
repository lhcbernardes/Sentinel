use crate::blocking::blocklist::{BlockType, Blocklist};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

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

        let urls: Vec<String> = content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
            .map(|s| s.trim().to_string())
            .collect();

        tracing::info!("Found {} blocklist URLs to process in parallel", urls.len());

        let semaphore = Arc::new(Semaphore::new(10));
        let client = Arc::new(client);
        let blocklist = self.blocklist.clone();

        let futures: Vec<_> = urls.into_iter().enumerate().map(|(i, url)| {
            let sem = semaphore.clone();
            let _client = client.clone();
            let blocklist = blocklist.clone();
            
            tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                
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

                match blocklist.load_from_url(&url, block_type).await {
                    Ok(count) => {
                        tracing::info!("[{}] Loaded {} entries from {}", i + 1, count, url);
                        (block_type, count, true)
                    }
                    Err(e) => {
                        tracing::warn!("[{}] Failed to load {}: {}", i + 1, url, e);
                        (block_type, 0, false)
                    }
                }
            })
        }).collect();

        let results = futures::future::join_all(futures).await;

        let mut total_trackers = 0;
        let mut total_malware = 0;

        for result in results {
            if let Ok((block_type, count, _)) = result {
                if block_type == BlockType::Tracker {
                    total_trackers += count;
                } else {
                    total_malware += count;
                }
            }
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

        self.load_urls_parallel(trackers, BlockType::Tracker).await
    }

    pub async fn update_malware(&self) -> Result<usize, String> {
        let malware = vec![
            "https://v.firebog.net/hosts/Prigent-Malware.txt",
            "https://v.firebog.net/hosts/RPiList-Malware.txt",
            "https://v.firebog.net/hosts/RPiList-Phishing.txt",
            "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
            "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt",
        ];

        self.load_urls_parallel(malware, BlockType::Malware).await
    }

    pub async fn update_attackers(&self) -> Result<usize, String> {
        let attackers = vec![
            "https://phishunt.io/feed.txt",
            "https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt",
        ];

        self.load_urls_parallel(attackers, BlockType::Attacker).await
    }

    async fn load_urls_parallel(&self, urls: Vec<&str>, block_type: BlockType) -> Result<usize, String> {
        let semaphore = Arc::new(Semaphore::new(10));
        let blocklist = self.blocklist.clone();
        
        let urls: Vec<String> = urls.into_iter().map(|s| s.to_string()).collect();

        let futures: Vec<_> = urls.into_iter().enumerate().map(|(_i, url)| {
            let sem = semaphore.clone();
            let blocklist = blocklist.clone();
            
            tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                
                match blocklist.load_from_url(&url, block_type).await {
                    Ok(count) => {
                        tracing::info!("Loaded {} entries from {}", count, url);
                        count
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load {}: {}", url, e);
                        0
                    }
                }
            })
        }).collect();

        let results = futures::future::join_all(futures).await;
        let total: usize = results.into_iter()
            .map(|r| r.unwrap_or(0))
            .sum();

        Ok(total)
    }
}
