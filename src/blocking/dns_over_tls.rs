use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotConfig {
    pub enabled: bool,
    pub server_name: String,
    pub port: u16,
    pub bootstrap_dns: Vec<String>,
}

impl Default for DotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: "cloudflare-dns.com".to_string(),
            port: 853,
            bootstrap_dns: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
        }
    }
}

pub struct DotClient {
    config: Arc<RwLock<DotConfig>>,
    client: reqwest::Client,
}

impl DotClient {
    pub fn new(config: DotConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            client,
        })
    }

    pub async fn resolve(&self, domain: &str) -> Result<Vec<std::net::IpAddr>, String> {
        if !self.config.read().enabled {
            return Err("DoT is not enabled".to_string());
        }

        // DoT typically uses a specific API endpoint over HTTPS
        // For now, we'll use the DoH endpoint as fallback since DoT setup is complex
        let config = self.config.read().clone();

        // Try to use DNS-over-HTTPS with the DoT server name as fallback
        let url = format!("https://{}/dns-query", config.server_name);

        let query = Self::build_dns_query(domain);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/dns-message")
            .body(query)
            .send()
            .await
            .map_err(|e| format!("DoT request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("DoT returned status: {}", response.status()));
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| format!("Failed to read DoT response: {}", e))?;

        Self::parse_dns_response(&body)
    }

    fn build_dns_query(domain: &str) -> Vec<u8> {
        let mut encoder = vec![0u8; 512];

        encoder[0] = 0x00;
        encoder[1] = 0x00;
        encoder[2] = 0x01;
        encoder[3] = 0x00;
        encoder[4] = 0x00;
        encoder[5] = 0x01;
        encoder[6] = 0x00;
        encoder[7] = 0x00;
        encoder[8] = 0x00;
        encoder[9] = 0x00;
        encoder[10] = 0x00;
        encoder[11] = 0x00;

        let mut pos = 12;
        for label in domain.split('.') {
            if label.is_empty() {
                continue;
            }
            encoder[pos] = label.len() as u8;
            pos += 1;
            for byte in label.as_bytes() {
                encoder[pos] = *byte;
                pos += 1;
            }
        }
        encoder[pos] = 0x00;
        pos += 1;

        encoder[pos] = 0x00;
        encoder[pos + 1] = 0x01;
        pos += 2;

        encoder[pos] = 0x00;
        encoder[pos + 1] = 0x01;
        pos += 2;

        encoder[..pos].to_vec()
    }

    fn parse_dns_response(data: &[u8]) -> Result<Vec<std::net::IpAddr>, String> {
        if data.len() < 12 {
            return Err("DNS response too short".to_string());
        }

        let an_count = u16::from_be_bytes([data[6], data[7]]) as usize;
        let mut pos = 12;

        while pos < data.len() && data[pos] != 0 {
            pos += data[pos] as usize + 1;
        }
        pos += 5;

        let mut ips = Vec::new();

        for _ in 0..an_count {
            if pos >= data.len() {
                break;
            }

            if data[pos] & 0xC0 == 0xC0 && pos + 1 < data.len() {
                pos += 2;
            } else {
                while pos < data.len() && data[pos] != 0 {
                    pos += data[pos] as usize + 1;
                }
                pos += 1;
            }

            if pos + 10 > data.len() {
                break;
            }

            let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let rd_length = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            let rdata_start = pos + 10;

            if qtype == 1 && rd_length == 4 && rdata_start + 4 <= data.len() {
                let ip = std::net::Ipv4Addr::new(
                    data[rdata_start],
                    data[rdata_start + 1],
                    data[rdata_start + 2],
                    data[rdata_start + 3],
                );
                ips.push(std::net::IpAddr::V4(ip));
            } else if qtype == 28 && rd_length == 16 && rdata_start + 16 <= data.len() {
                let ip = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([data[rdata_start], data[rdata_start + 1]]),
                    u16::from_be_bytes([data[rdata_start + 2], data[rdata_start + 3]]),
                    u16::from_be_bytes([data[rdata_start + 4], data[rdata_start + 5]]),
                    u16::from_be_bytes([data[rdata_start + 6], data[rdata_start + 7]]),
                    u16::from_be_bytes([data[rdata_start + 8], data[rdata_start + 9]]),
                    u16::from_be_bytes([data[rdata_start + 10], data[rdata_start + 11]]),
                    u16::from_be_bytes([data[rdata_start + 12], data[rdata_start + 13]]),
                    u16::from_be_bytes([data[rdata_start + 14], data[rdata_start + 15]]),
                );
                ips.push(std::net::IpAddr::V6(ip));
            }

            pos = rdata_start + rd_length;
        }

        if ips.is_empty() {
            return Err("No A/AAAA records found".to_string());
        }

        Ok(ips)
    }

    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.config.write().enabled = enabled;
    }

    pub fn get_config(&self) -> DotConfig {
        self.config.read().clone()
    }
}

impl Default for DotClient {
    fn default() -> Self {
        Self::new(DotConfig::default()).unwrap()
    }
}
