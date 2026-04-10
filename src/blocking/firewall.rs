use parking_lot::RwLock;
use std::collections::HashSet;
use std::env;
use std::process::Command;
use std::sync::Arc;

use crate::blocking::blocklist::Blocklist;

/// Valida e normaliza um endereço IP usando o parser da stdlib.
/// Retorna o IP normalizado (ex: "::1" → "::1") ou um erro descritivo.
fn validate_ip(ip: &str) -> Result<String, String> {
    let ip = ip.trim();
    ip.parse::<std::net::IpAddr>()
        .map(|addr| addr.to_string())
        .map_err(|_| format!("Endereço IP inválido: '{}'", ip))
}


#[derive(Clone)]
pub enum FirewallBackend {
    Iptables,
    Pf,
    None,
}

pub struct FirewallManager {
    blocklist: Arc<Blocklist>,
    blocked_ips: RwLock<HashSet<String>>,
    chain_name: String,
    enabled: RwLock<bool>,
    backend: RwLock<FirewallBackend>,
}

impl FirewallManager {
    pub fn new(blocklist: Arc<Blocklist>, chain_name: &str) -> Self {
        let backend = Self::detect_backend();

        Self {
            blocklist,
            blocked_ips: RwLock::new(HashSet::new()),
            chain_name: chain_name.to_string(),
            enabled: RwLock::new(false),
            backend: RwLock::new(backend),
        }
    }

    fn detect_backend() -> FirewallBackend {
        match env::consts::OS {
            "linux" => FirewallBackend::Iptables,
            "macos" => FirewallBackend::Pf,
            _ => FirewallBackend::None,
        }
    }

    pub fn init(&self) -> Result<(), String> {
        let backend = self.backend.read().clone();

        match backend {
            FirewallBackend::Iptables => self.init_iptables(),
            FirewallBackend::Pf => self.init_pf(),
            FirewallBackend::None => {
                *self.enabled.write() = true;
                tracing::info!("Firewall disabled (unsupported platform)");
                Ok(())
            }
        }
    }

    fn init_iptables(&self) -> Result<(), String> {
        let chain = &self.chain_name;

        let check = Command::new("iptables").args(["-L", chain, "-n"]).output();

        match check {
            Ok(output) if output.status.success() => {
                let _ = Command::new("iptables").args(["-F", chain]).output();
            }
            _ => {
                let output = Command::new("iptables")
                    .args(["-N", chain])
                    .output()
                    .map_err(|e| format!("Failed to create iptables chain: {}", e))?;

                if !output.status.success() {
                    return Err("Failed to create iptables chain (need root?)".to_string());
                }
            }
        }

        let _ = Command::new("iptables")
            .args(["-I", "INPUT", "-j", chain])
            .output();

        *self.enabled.write() = true;
        tracing::info!(
            "Firewall manager initialized with iptables chain: {}",
            chain
        );

        Ok(())
    }

    fn init_pf(&self) -> Result<(), String> {
        // macOS uses pf (Packet Filter)
        // Create anchor for Sentinel-RS rules
        let _chain = &self.chain_name;

        // Check if pf is enabled
        let status = Command::new("pfctl").args(["-s", "all"]).output();

        if status.is_err() {
            return Err("pfctl not available".to_string());
        }

        *self.enabled.write() = true;
        tracing::info!("Firewall manager initialized with pf (macOS)");

        Ok(())
    }

    pub fn block_ip(&self, ip: &str) -> Result<(), String> {
        // Validate IP to prevent command injection
        let validated_ip = validate_ip(ip)?;

        let mut blocked = self.blocked_ips.write();

        if blocked.contains(&validated_ip) {
            return Ok(());
        }

        let backend = self.backend.read().clone();

        match backend {
            FirewallBackend::Iptables => {
                let output = Command::new("iptables")
                    .args([
                        "-A",
                        &self.chain_name,
                        "-s",
                        &validated_ip,
                        "-j",
                        "DROP",
                        "-m",
                        "comment",
                        "--comment",
                        "Sentinel-RS blocked",
                    ])
                    .output()
                    .map_err(|e| format!("Failed to execute iptables: {}", e))?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("iptables error: {}", stderr));
                }
            }
            FirewallBackend::Pf => {
                // macOS pf rule
                if let Ok(output) = Command::new("pfctl")
                    .args(["-k", "from", ip, "-k", "all"])
                    .output()
                {
                    if !output.status.success() {
                        tracing::warn!("pfctl block warning for {}", ip);
                    }
                }
            }
            FirewallBackend::None => {
                tracing::info!("Blocking {} (simulation only - platform not supported)", ip);
            }
        }

        self.blocklist.add_attacker(ip.to_string());
        blocked.insert(ip.to_string());
        tracing::info!("Blocked IP: {}", ip);

        Ok(())
    }

    pub fn unblock_ip(&self, ip: &str) -> Result<(), String> {
        let mut blocked = self.blocked_ips.write();

        if !blocked.contains(ip) {
            return Ok(());
        }

        let backend = self.backend.read().clone();

        match backend {
            FirewallBackend::Iptables => {
                let _ = Command::new("iptables")
                    .args(["-D", &self.chain_name, "-s", ip, "-j", "DROP"])
                    .output();
            }
            FirewallBackend::Pf => {
                // pf doesn't have easy unblock, just remove from our list
                tracing::info!("Unblocked {} (removed from tracking)", ip);
            }
            FirewallBackend::None => {}
        }

        blocked.remove(ip);
        tracing::info!("Unblocked IP: {}", ip);

        Ok(())
    }

    pub fn block_port_scan(&self, ip: &str) -> Result<(), String> {
        self.block_ip(ip)
    }

    pub fn get_blocked_ips(&self) -> Vec<String> {
        self.blocked_ips.read().iter().cloned().collect()
    }

    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    pub fn enable(&self) {
        *self.enabled.write() = true;
    }

    pub fn disable(&self) {
        *self.enabled.write() = false;
    }

    pub fn stats(&self) -> FirewallStats {
        let backend = match self.backend.read().clone() {
            FirewallBackend::Iptables => "iptables",
            FirewallBackend::Pf => "pf",
            FirewallBackend::None => "none",
        };

        FirewallStats {
            enabled: *self.enabled.read(),
            blocked_count: self.blocked_ips.read().len(),
            chain_name: self.chain_name.clone(),
            backend: backend.to_string(),
        }
    }

    pub fn cleanup(&self) {
        let backend = self.backend.read().clone();

        match backend {
            FirewallBackend::Iptables => {
                let _ = Command::new("iptables")
                    .args(["-D", "INPUT", "-j", &self.chain_name])
                    .output();
                let _ = Command::new("iptables")
                    .args(["-F", &self.chain_name])
                    .output();
                let _ = Command::new("iptables")
                    .args(["-X", &self.chain_name])
                    .output();
            }
            FirewallBackend::Pf => {
                // pf doesn't need cleanup for our simple rules
            }
            FirewallBackend::None => {}
        }

        *self.enabled.write() = false;
        tracing::info!("Firewall manager cleaned up");
    }
}

impl Drop for FirewallManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FirewallStats {
    pub enabled: bool,
    pub blocked_count: usize,
    pub chain_name: String,
    pub backend: String,
}
