use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub expires: i64,
    pub state: LeaseState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseState {
    Active,
    Expired,
    Rebinding,
    Renewing,
}

pub struct DhcpMonitor {
    leases: RwLock<HashMap<String, DhcpLease>>,
    server_info: RwLock<Option<DhcpServerInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpServerInfo {
    pub server_ip: String,
    pub range_start: String,
    pub range_end: String,
    pub subnet: String,
    pub gateway: String,
    pub dns_servers: Vec<String>,
}

impl DhcpMonitor {
    pub fn new() -> Self {
        Self {
            leases: RwLock::new(HashMap::new()),
            server_info: RwLock::new(None),
        }
    }

    pub fn refresh_leases(&self) {
        #[cfg(target_os = "linux")]
        {
            // Try different lease file locations
            let paths = [
                "/var/lib/dhcp/dhcpd.leases",
                "/var/lib/dhcpd/dhcpd.leases",
                "/var/lib/NetworkManager/dhclient-leases",
                "/var/lib/NetworkManager/dhcp-*.lease",
            ];

            for path_pattern in &paths {
                if path_pattern.contains('*') {
                    // Handle glob pattern
                    if let Ok(entries) = glob::glob(path_pattern) {
                        for entry in entries.flatten() {
                            if let Ok(content) = std::fs::read_to_string(&entry) {
                                self.parse_linux_leases(&content);
                                return;
                            }
                        }
                    }
                } else if std::path::Path::new(path_pattern).exists() {
                    if let Ok(content) = std::fs::read_to_string(path_pattern) {
                        self.parse_linux_leases(&content);
                        return;
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: check IP configuration
            let output = Command::new("ipconfig").args(["getpacket", "en0"]).output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                self.parse_macos_dhcp(&stdout);
            }
        }
    }

    #[allow(dead_code)]
    fn parse_linux_leases(&self, content: &str) {
        let mut leases = self.leases.write();
        leases.clear();

        let mut current_lease: Option<DhcpLease> = None;

        for line in content.lines() {
            let line = line.trim();

            if line.starts_with("lease ") {
                if let Some(lease) = current_lease.take() {
                    if lease.state == LeaseState::Active {
                        leases.insert(lease.mac.clone(), lease);
                    }
                }

                // Parse: lease 192.168.1.100 {
                if let Some(ip_start) = line.find("lease ") {
                    if let Some(ip_end) = line.find(" {") {
                        let ip = line[ip_start + 7..ip_end].to_string();
                        current_lease = Some(DhcpLease {
                            ip,
                            mac: String::new(),
                            hostname: None,
                            expires: 0,
                            state: LeaseState::Active,
                        });
                    }
                }
            } else if line.starts_with("hardware ethernet ") {
                if let Some(ref mut lease) = current_lease {
                    if let Some(mac_start) = line.find("hardware ethernet ") {
                        let mac = line[mac_start + 18..]
                            .trim()
                            .trim_end_matches(';')
                            .to_string();
                        lease.mac = mac;
                    }
                }
            } else if line.starts_with("client-hostname ") {
                if let Some(ref mut lease) = current_lease {
                    if let Some(name_start) = line.find("client-hostname ") {
                        let hostname = line[name_start + 16..]
                            .trim()
                            .trim_end_matches(';')
                            .to_string();
                        lease.hostname = Some(hostname);
                    }
                }
            }
        }

        if let Some(lease) = current_lease {
            if lease.state == LeaseState::Active && !lease.mac.is_empty() {
                leases.insert(lease.mac.clone(), lease);
            }
        }
    }

    fn parse_macos_dhcp(&self, content: &str) {
        let mut leases = self.leases.write();

        for line in content.lines() {
            if line.contains("yiaddr") {
                // Extract IP
                if let Some(start) = line.find("yiaddr = ") {
                    let ip = line[start + 10..]
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string();

                    let lease = DhcpLease {
                        ip: ip.clone(),
                        mac: String::new(),
                        hostname: None,
                        expires: 0,
                        state: LeaseState::Active,
                    };

                    leases.insert(ip, lease);
                }
            }
        }
    }

    pub fn get_leases(&self) -> Vec<DhcpLease> {
        self.leases.read().values().cloned().collect()
    }

    pub fn get_lease_by_ip(&self, ip: &str) -> Option<DhcpLease> {
        self.leases.read().get(ip).cloned()
    }

    pub fn get_lease_by_mac(&self, mac: &str) -> Option<DhcpLease> {
        let leases = self.leases.read();
        leases
            .values()
            .find(|l| l.mac.to_lowercase() == mac.to_lowercase())
            .cloned()
    }

    pub fn get_server_info(&self) -> Option<DhcpServerInfo> {
        self.server_info.read().clone()
    }

    pub fn set_server_info(&self, info: DhcpServerInfo) {
        *self.server_info.write() = Some(info);
    }

    pub fn get_stats(&self) -> DhcpStats {
        let leases = self.leases.read();

        DhcpStats {
            total_leases: leases.len(),
            active_leases: leases
                .values()
                .filter(|l| l.state == LeaseState::Active)
                .count(),
            expired_leases: leases
                .values()
                .filter(|l| l.state == LeaseState::Expired)
                .count(),
            server_info: self.server_info.read().clone(),
        }
    }
}

impl Default for DhcpMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpStats {
    pub total_leases: usize,
    pub active_leases: usize,
    pub expired_leases: usize,
    pub server_info: Option<DhcpServerInfo>,
}
