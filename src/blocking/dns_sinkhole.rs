use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;

use crate::blocking::blocklist::Blocklist;
use crate::blocking::dns_rewrite::DnsRewriteManager;

#[derive(Clone)]
struct CachedResponse {
    data: Vec<u8>,
    expires_at: Instant,
}

impl CachedResponse {
    fn new(data: Vec<u8>, ttl_secs: u64) -> Self {
        Self {
            data,
            expires_at: Instant::now() + std::time::Duration::from_secs(ttl_secs),
        }
    }
    
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

pub struct DnsSinkhole {
    blocklist: Arc<Blocklist>,
    rewrite_manager: Arc<DnsRewriteManager>,
    blocked_count: AtomicU64,
    query_count: AtomicU64,
    allow_fallback: bool,
    platform_supported: RwLock<bool>,
    cache: DashMap<String, CachedResponse>,
    query_log: RwLock<VecDeque<DnsQueryRecord>>,
}

impl DnsSinkhole {
    pub fn new(blocklist: Arc<Blocklist>, rewrite_manager: Arc<DnsRewriteManager>, allow_fallback: bool) -> Self {
        let platform_supported = Self::check_platform_support();

        let sinkhole = Self {
            blocklist,
            rewrite_manager,
            blocked_count: AtomicU64::new(0),
            query_count: AtomicU64::new(0),
            allow_fallback,
            platform_supported: RwLock::new(platform_supported),
            cache: DashMap::new(),
            query_log: RwLock::new(VecDeque::with_capacity(5000)),
        };

        // Pre-load common domains for faster initial lookups
        sinkhole.preload_common_domains();
        sinkhole
    }

    fn preload_common_domains(&self) {
        let common_domains = vec![
            "google.com", "google-analytics.com", "doubleclick.net",
            "facebook.com", "fbcdn.net", "amazon.com", "aws.amazon.com",
            "microsoft.com", "apple.com", "netflix.com"
        ];
        
        for domain in common_domains {
            // We just warm up the cache or blocklist checks if needed.
            // For now, we pre-warm the blocklist check if it's expensive.
            let _ = self.blocklist.is_blocked(domain);
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
                    // Pass client address to handle_query (no double-counting here)
                    let response = self.handle_query(&buf[..len], &addr.ip().to_string());
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

    fn handle_query(&self, packet: &[u8], client_ip: &str) -> Option<Vec<u8>> {
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

        // Check cache first - DashMap provides lock-free reads
        if let Some(cached) = self.cache.get(domain_lower.as_str()) {
            if !cached.is_expired() {
                return Some(cached.data.clone());
            }
        }

        // Count query atomically
        self.query_count.fetch_add(1, Ordering::Relaxed);
        
        // 1. Check for local rewrite overrides first
        let local_rewrite = if self.rewrite_manager.is_enabled() {
            self.rewrite_manager.lookup(&domain_lower)
        } else {
            None
        };
        
        let is_blocked = if local_rewrite.is_none() {
            self.blocklist.is_blocked(&domain_lower)
        } else {
            false
        };

        // Extract the question section from the original packet for inclusion in responses
        let question_section = self.extract_question_section(packet);

        let record = DnsQueryRecord {
            timestamp: chrono::Utc::now().timestamp_millis(),
            client_ip: client_ip.to_string(),
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

        tracing::debug!("DNS query for: {} from {}", domain_lower, client_ip);

        let response = if let Some(ip) = local_rewrite {
            tracing::debug!("Local rewrite for: {} to {}", domain_lower, ip);
            self.create_a_response(id, &question_section, ip)
        } else if is_blocked {
            self.blocked_count.fetch_add(1, Ordering::Relaxed);
            tracing::info!("Blocked DNS query for: {} from {}", domain_lower, client_ip);
            self.create_nxdomain_response(id, &question_section)
        } else if self.allow_fallback {
            self.create_localhost_response(id, &question_section)
        } else {
            return None;
        };

        // Cache the response with a more granular TTL (30 seconds)
        let cached_response = CachedResponse::new(response.clone(), 30);
        self.cache.insert(domain_lower, cached_response);

        Some(response)
    }

    fn extract_domain(&self, packet: &[u8]) -> Option<String> {
        let mut domain = String::new();
        let mut pos = 12;

        while pos < packet.len() {
            let len = packet[pos] as usize;

            // Check for DNS compression pointer (top 2 bits set)
            if len & 0xC0 == 0xC0 {
                // Compression pointer — skip it (2 bytes) and stop
                break;
            }

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

    /// Extract the raw question section bytes from a DNS packet (everything from
    /// byte 12 to the end of the first question: name + QTYPE(2) + QCLASS(2)).
    fn extract_question_section(&self, packet: &[u8]) -> Vec<u8> {
        let mut pos = 12;
        while pos < packet.len() {
            let len = packet[pos] as usize;
            if len == 0 {
                pos += 1; // skip the null terminator
                break;
            }
            if len & 0xC0 == 0xC0 {
                pos += 2; // skip compression pointer
                break;
            }
            pos += len + 1;
        }
        // Include QTYPE (2 bytes) + QCLASS (2 bytes)
        let end = (pos + 4).min(packet.len());
        packet[12..end].to_vec()
    }

    fn create_nxdomain_response(&self, id: u16, question: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(12 + question.len());

        // Header
        response.extend_from_slice(&id.to_be_bytes()); // Transaction ID
        response.extend_from_slice(&[0x81, 0x83]); // Flags: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        response.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Echo back the original question section
        response.extend_from_slice(question);

        response
    }

    fn create_localhost_response(&self, id: u16, question: &[u8]) -> Vec<u8> {
        self.create_a_response(id, question, std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
    }

    fn create_a_response(&self, id: u16, question: &[u8], ip: std::net::IpAddr) -> Vec<u8> {
        let mut response = Vec::with_capacity(12 + question.len() + 16);

        // Header
        response.extend_from_slice(&id.to_be_bytes()); // Transaction ID
        response.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, RD=1, RA=1, RCODE=0 (NOERROR)
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        response.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Echo back the original question section
        response.extend_from_slice(question);

        // Answer section: point back to the name in the question (compression pointer 0xC00C)
        response.extend_from_slice(&[0xC0, 0x0C]); // Name: pointer to offset 12 (question name)
        
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                response.extend_from_slice(&[0x00, 0x01]); // TYPE: A (1)
                response.extend_from_slice(&[0x00, 0x01]); // CLASS: IN (1)
                response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL: 300 seconds
                response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH: 4 bytes
                response.extend_from_slice(&ipv4.octets()); // RDATA
            }
            std::net::IpAddr::V6(ipv6) => {
                response.extend_from_slice(&[0x00, 0x1C]); // TYPE: AAAA (28)
                response.extend_from_slice(&[0x00, 0x01]); // CLASS: IN (1)
                response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL: 300 seconds
                response.extend_from_slice(&[0x00, 0x10]); // RDLENGTH: 16 bytes
                response.extend_from_slice(&ipv6.octets()); // RDATA
            }
        }

        response
    }

    pub fn stats(&self) -> DnsStats {
        DnsStats {
            queries: self.query_count.load(Ordering::Relaxed),
            blocked: self.blocked_count.load(Ordering::Relaxed),
            platform_supported: *self.platform_supported.read(),
            cache_size: self.cache.len(),
        }
    }

    pub fn is_supported(&self) -> bool {
        *self.platform_supported.read()
    }

    /// Clean up expired cache entries
    pub fn cleanup_cache(&self) {
        self.cache.retain(|_, cached| !cached.is_expired());
    }

    /// Get cache hit rate statistics
    pub fn cache_stats(&self) -> CacheStats {
        let total_entries = self.cache.len();
        let expired_count = self.cache.iter().filter(|r| r.value().is_expired()).count();
        
        CacheStats {
            total_entries,
            expired_count,
            active_entries: total_entries - expired_count,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_count: usize,
    pub active_entries: usize,
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
