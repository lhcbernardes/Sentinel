use crossbeam_channel::{bounded, Sender};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::env;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crate::blocking::blocklist::Blocklist;
use bloomfilter::Bloom;

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

enum FirewallCommand {
    Block { ip: String },
    Unblock { ip: String },
    Shutdown,
}

pub struct FirewallManager {
    #[allow(dead_code)]
    blocklist: Arc<Blocklist>,
    blocked_ips: RwLock<HashSet<String>>,
    chain_name: String,
    enabled: RwLock<bool>,
    backend: RwLock<FirewallBackend>,
    cmd_tx: Sender<FirewallCommand>,
    shutdown: Arc<AtomicBool>,
    bloom_filter: RwLock<Bloom<String>>,
}

impl FirewallManager {
    pub fn new(blocklist: Arc<Blocklist>, chain_name: &str) -> Self {
        let backend = Self::detect_backend();
        let (cmd_tx, cmd_rx) = bounded(1000);
        let shutdown = Arc::new(AtomicBool::new(false));

        let chain_name_owned = chain_name.to_string();
        let backend_clone = backend.clone();
        let blocklist_clone = blocklist.clone();
        let shutdown_clone = shutdown.clone();

        thread::spawn(move || {
            Self::worker_loop(
                cmd_rx,
                chain_name_owned,
                backend_clone,
                blocklist_clone,
                shutdown_clone,
            );
        });

        Self {
            blocklist,
            blocked_ips: RwLock::new(HashSet::new()),
            chain_name: chain_name.to_string(),
            enabled: RwLock::new(false),
            backend: RwLock::new(backend),
            cmd_tx,
            shutdown,
            bloom_filter: RwLock::new(Bloom::new_for_fp_rate(100000, 0.01)),
        }
    }

    fn worker_loop(
        cmd_rx: crossbeam_channel::Receiver<FirewallCommand>,
        chain_name: String,
        backend: FirewallBackend,
        blocklist: Arc<Blocklist>,
        shutdown: Arc<AtomicBool>,
    ) {
        loop {
            match cmd_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(FirewallCommand::Block { ip }) => {
                    if !Self::execute_block(&chain_name, &backend, &ip) {
                        tracing::warn!("Failed to block IP: {}", ip);
                    } else {
                        blocklist.add_attacker(ip.clone());
                        tracing::info!("Blocked IP: {}", ip);
                    }
                }
                Ok(FirewallCommand::Unblock { ip }) => {
                    Self::execute_unblock(&chain_name, &backend, &ip);
                    tracing::info!("Unblocked IP: {}", ip);
                }
                Ok(FirewallCommand::Shutdown) => break,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        }
        tracing::info!("Firewall worker thread stopped");
    }

    fn execute_block(chain_name: &str, backend: &FirewallBackend, ip: &str) -> bool {
        match backend {
            FirewallBackend::Iptables => Command::new("iptables")
                .args([
                    "-A",
                    chain_name,
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    "Sentinel-RS blocked",
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
            FirewallBackend::Pf => Command::new("pfctl")
                .args(["-k", "from", ip, "-k", "all"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
            FirewallBackend::None => {
                tracing::info!("Blocking {} (simulation only)", ip);
                true
            }
        }
    }

    fn execute_unblock(chain_name: &str, backend: &FirewallBackend, ip: &str) {
        match backend {
            FirewallBackend::Iptables => {
                let _ = Command::new("iptables")
                    .args(["-D", chain_name, "-s", ip, "-j", "DROP"])
                    .output();
            }
            FirewallBackend::Pf => {
                tracing::info!("Unblocked {} (pf - removed from tracking)", ip);
            }
            FirewallBackend::None => {}
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
        let _chain = &self.chain_name;

        let status = Command::new("pfctl").args(["-s", "all"]).output();

        if status.is_err() {
            return Err("pfctl not available".to_string());
        }

        *self.enabled.write() = true;
        tracing::info!("Firewall manager initialized with pf (macOS)");

        Ok(())
    }

    pub fn block_ip(&self, ip: &str) -> Result<(), String> {
        let validated_ip = validate_ip(ip)?;

        {
            let mut blocked = self.blocked_ips.write();
            if blocked.contains(&validated_ip) {
                return Ok(());
            }
            blocked.insert(validated_ip.clone());
            
            // Update bloom filter
            self.bloom_filter.write().set(&validated_ip);
        }

        let _ = self
            .cmd_tx
            .try_send(FirewallCommand::Block { ip: validated_ip });

        Ok(())
    }
    
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        // Fast check using bloom filter
        if !self.bloom_filter.read().check(&ip.to_string()) {
            return false;
        }
        
        // Potential positive, confirm with HashSet
        self.blocked_ips.read().contains(ip)
    }

    pub fn unblock_ip(&self, ip: &str) -> Result<(), String> {
        let validated_ip = validate_ip(ip)?;

        {
            let mut blocked = self.blocked_ips.write();
            if !blocked.contains(&validated_ip) {
                return Ok(());
            }
            blocked.remove(&validated_ip);
        }

        let _ = self
            .cmd_tx
            .try_send(FirewallCommand::Unblock { ip: validated_ip });

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

    fn cleanup_sync(&self) {
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
            FirewallBackend::Pf => {}
            FirewallBackend::None => {}
        }

        *self.enabled.write() = false;
    }

    pub fn cleanup(&self) {
        self.cleanup_sync();
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.cmd_tx.send(FirewallCommand::Shutdown);
        tracing::info!("Firewall manager cleaned up");
    }
}

impl Drop for FirewallManager {
    fn drop(&mut self) {
        self.cleanup_sync();
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.cmd_tx.send(FirewallCommand::Shutdown);
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FirewallStats {
    pub enabled: bool,
    pub blocked_count: usize,
    pub chain_name: String,
    pub backend: String,
}
