use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::blocking::blocklist::Blocklist;

pub struct DnsSinkhole {
    blocklist: Arc<Blocklist>,
    blocked_count: RwLock<u64>,
    query_count: RwLock<u64>,
    allow_fallback: bool,
    platform_supported: RwLock<bool>,
    cache: RwLock<HashMap<String, Vec<u8>>>,
    query_log: RwLock<VecDeque<DnsQueryRecord>>,
}

impl DnsSinkhole {
    pub fn new(blocklist: Arc<Blocklist>, allow_fallback: bool) -> Self {
        let platform_supported = Self::check_platform_support();

        Self {
            blocklist,
            blocked_count: RwLock::new(0),
            query_count: RwLock::new(0),
            allow_fallback,
            platform_supported: RwLock::new(platform_supported),
            cache: RwLock::new(HashMap::new()),
            query_log: RwLock::new(VecDeque::with_capacity(100)),
        }
    }

    fn check_platform_support() -> bool {
        #[cfg(unix)]
        return true;

        #[cfg(not(unix))]
        return false;
    }

    pub async fn start(&self, port: u16) -> Result<(), String> {
        if !*self.platform_supported.read() {
            return Err("DNS sinkhole not supported on this platform".to_string());
        }

        let addr = format!("0.0.0.0:{}", port);

        match UdpSocket::bind(&addr).await {
            Ok(socket) => {
                tracing::info!("DNS Sinkhole listening on UDP {}", addr);
                self.run_udp(socket).await;
            }
            Err(e) => {
                // On macOS, privileged ports require root
                // Try alternative binding or warn
                if e.kind() == std::io::ErrorKind::PermissionDenied && port < 1024 {
                    tracing::warn!("DNS on port {} requires root. Trying alternative.", port);
                    // Fallback to non-privileged port
                    let alt_addr = format!("0.0.0.0:{}", 5353);
                    match UdpSocket::bind(&alt_addr).await {
                        Ok(socket) => {
                            tracing::info!("DNS Sinkhole listening on UDP {} (fallback)", alt_addr);
                            self.run_udp(socket).await;
                        }
                        Err(e2) => {
                            return Err(format!("Failed to bind DNS: {}", e2));
                        }
                    }
                } else {
                    return Err(format!("Failed to bind: {}", e));
                }
            }
        }

        Ok(())
    }

    async fn run_udp(&self, socket: tokio::net::UdpSocket) {
        let mut buf = [0u8; 512];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    *self.query_count.write() += 1;
                    let response = self.handle_query(&buf[..len]);
                    if let Some(resp) = response {
                        let _ = socket.send_to(&resp, addr).await;
                    }
                }
                Err(e) => {
                    tracing::warn!("DNS recv error: {}", e);
                }
            }
        }
    }

    fn handle_query(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        let qr = (flags >> 15) & 1;

        if qr != 0 {
            return None;
        }

        let domain = self.extract_domain(packet)?;
        let domain_lower = domain.to_lowercase();

        *self.query_count.write() += 1;

        let is_blocked = self.blocklist.is_blocked(&domain_lower);

        let record = DnsQueryRecord {
            timestamp: chrono::Utc::now().timestamp_millis(),
            client_ip: "0.0.0.0".to_string(),
            domain: domain_lower.clone(),
            blocked: is_blocked,
            block_type: if is_blocked {
                Some("blocklist".to_string())
            } else {
                None
            },
        };

        {
            let mut log = self.query_log.write();
            if log.len() >= 100 {
                log.pop_front();
            }
            log.push_back(record);
        }

        tracing::debug!("DNS query for: {}", domain_lower);

        if is_blocked {
            *self.blocked_count.write() += 1;
            tracing::info!("Blocked DNS query for: {}", domain_lower);

            return Some(self.create_nxdomain_response(id));
        }

        if self.allow_fallback {
            return Some(self.create_localhost_response(id));
        }

        None
    }

    fn extract_domain(&self, packet: &[u8]) -> Option<String> {
        let mut domain = String::new();
        let mut pos = 12;

        while pos < packet.len() {
            let len = packet[pos] as usize;
            if len == 0 {
                break;
            }

            if pos + len + 1 > packet.len() {
                return None;
            }

            if !domain.is_empty() {
                domain.push('.');
            }

            domain.push_str(&String::from_utf8_lossy(&packet[pos + 1..pos + 1 + len]));
            pos += len + 1;
        }

        if domain.is_empty() {
            None
        } else {
            Some(domain)
        }
    }

    fn create_nxdomain_response(&self, id: u16) -> Vec<u8> {
        let mut response = Vec::with_capacity(32);

        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&[0x81, 0x83]);
        response.extend_from_slice(&[0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x00, 0x00]);

        response
    }

    fn create_localhost_response(&self, id: u16) -> Vec<u8> {
        let mut response = Vec::with_capacity(32);

        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&[0x81, 0x80]);
        response.extend_from_slice(&[0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x00, 0x00]);

        response
    }

    pub fn stats(&self) -> DnsStats {
        DnsStats {
            queries: *self.query_count.read(),
            blocked: *self.blocked_count.read(),
            platform_supported: *self.platform_supported.read(),
            cache_size: self.cache.read().len(),
        }
    }

    pub fn is_supported(&self) -> bool {
        *self.platform_supported.read()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsStats {
    pub queries: u64,
    pub blocked: u64,
    pub platform_supported: bool,
    pub cache_size: usize,
}

impl DnsSinkhole {
    pub fn get_recent_queries(&self) -> Vec<DnsQueryRecord> {
        self.query_log
            .read()
            .iter()
            .rev()
            .take(100)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsQueryRecord {
    pub timestamp: i64,
    pub client_ip: String,
    pub domain: String,
    pub blocked: bool,
    pub block_type: Option<String>,
}
