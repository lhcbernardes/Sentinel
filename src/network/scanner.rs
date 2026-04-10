use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Mutex;

#[allow(dead_code)]
const VALID_IP_REGEX: &str = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$";

fn validate_subnet(subnet: &str) -> Result<String, String> {
    let subnet = subnet.trim();

    let dangerous_chars = [
        ';', '&', '|', '$', '`', '(', ')', '<', '>', '\n', '\r', '\0',
    ];
    for c in dangerous_chars {
        if subnet.contains(c) {
            return Err("Invalid subnet: contains forbidden characters".to_string());
        }
    }

    if !subnet.is_empty()
        && !subnet
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '/')
    {
        return Err("Invalid subnet: contains non-numeric characters".to_string());
    }

    if subnet.contains('/') {
        let parts: Vec<&str> = subnet.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR notation".to_string());
        }
        let mask: u8 = parts[1].parse().map_err(|_| "Invalid subnet mask")?;
        if mask > 32 {
            return Err("Subnet mask must be <= 32".to_string());
        }
    } else {
        let octets: Vec<&str> = subnet.split('.').collect();
        if octets.len() != 4 {
            return Err("Invalid IP address".to_string());
        }
        for octet in octets {
            let _num: u8 = octet.parse().map_err(|_| "Invalid IP octet")?;
        }
    }

    Ok(subnet.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub manufacturer: Option<String>,
    pub is_alive: bool,
    pub response_time_ms: Option<u64>,
}

pub struct NetworkScanner;

impl NetworkScanner {
    pub fn new() -> Self {
        Self
    }

    pub fn arp_scan(subnet: &str) -> Vec<ScanResult> {
        if let Err(e) = validate_subnet(subnet) {
            tracing::warn!("Invalid subnet input: {}", e);
            return Vec::new();
        }

        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("arp-scan")
                .args(["-l", "-g", "--interface", "eth0"])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ip = parts[0].to_string();
                        let mac = parts.get(1).map(|s| s.to_string());

                        if mac.is_some() {
                            results.push(ScanResult {
                                ip,
                                mac,
                                hostname: None,
                                manufacturer: None,
                                is_alive: true,
                                response_time_ms: None,
                            });
                        }
                    }
                }
            }

            if results.is_empty() {
                if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
                    for line in content.lines().skip(1) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let ip = parts[0].to_string();
                            let mac = parts[3].replace(":", ":");
                            if mac != "00:00:00:00:00:00" {
                                results.push(ScanResult {
                                    ip,
                                    mac: Some(mac),
                                    hostname: None,
                                    manufacturer: None,
                                    is_alive: true,
                                    response_time_ms: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("arp").args(["-a"]).output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(ip_start) = line.find('(') {
                        if let Some(ip_end) = line.find(')') {
                            let ip = line[ip_start + 1..ip_end].to_string();

                            if let Some(mac_start) = line.find("at ") {
                                if let Some(mac_end) = line[mac_start..].find(' ') {
                                    let mac = line[mac_start + 3..mac_start + 3 + mac_end].trim();
                                    if !mac.contains('?') && mac.contains(':') {
                                        results.push(ScanResult {
                                            ip,
                                            mac: Some(mac.to_string()),
                                            hostname: None,
                                            manufacturer: None,
                                            is_alive: true,
                                            response_time_ms: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        results
    }

    pub fn ping_host(ip: &str) -> Option<u64> {
        let start = std::time::Instant::now();

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("ping")
                .args(["-c", "1", "-W", "1", ip])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    return Some(start.elapsed().as_millis() as u64);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("ping")
                .args(["-c", "1", "-t", "1", ip])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    return Some(start.elapsed().as_millis() as u64);
                }
            }
        }

        None
    }

    pub fn quick_scan(subnet: &str) -> Vec<ScanResult> {
        let base_ip: String = subnet.chars().take_while(|c| *c != '.').collect();

        let results = Mutex::new(Vec::new());

        (1..255_u8).into_par_iter().for_each(|i| {
            let ip = format!("{}.{}", base_ip, i);
            if let Some(latency) = Self::ping_host(&ip) {
                let mut res = results.lock().unwrap();
                res.push(ScanResult {
                    ip,
                    mac: None,
                    hostname: None,
                    manufacturer: None,
                    is_alive: true,
                    response_time_ms: Some(latency),
                });
            }
        });

        let mut results = results.into_inner().unwrap();

        let arp_results = Self::arp_scan(subnet);
        for arp in arp_results {
            if !results.iter().any(|r: &ScanResult| r.ip == arp.ip) {
                results.push(arp);
            }
        }

        results
    }

    pub fn quick_scan_with_threads(subnet: &str, num_threads: usize) -> Vec<ScanResult> {
        let base_ip: String = subnet.chars().take_while(|c| *c != '.').collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

        let results = Mutex::new(Vec::new());

        pool.install(|| {
            (1..255_u8).into_par_iter().for_each(|i| {
                let ip = format!("{}.{}", base_ip, i);
                if let Some(latency) = Self::ping_host(&ip) {
                    let mut res = results.lock().unwrap();
                    res.push(ScanResult {
                        ip,
                        mac: None,
                        hostname: None,
                        manufacturer: None,
                        is_alive: true,
                        response_time_ms: Some(latency),
                    });
                }
            });
        });

        let mut results = results.into_inner().unwrap();

        let arp_results = Self::arp_scan(subnet);
        for arp in arp_results {
            if !results.iter().any(|r: &ScanResult| r.ip == arp.ip) {
                results.push(arp);
            }
        }

        results
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}
