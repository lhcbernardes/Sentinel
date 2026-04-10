use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub enabled: bool,
    pub provider: VpnProvider,
    pub interface: String,
    pub allowed_ips: Vec<String>,
    pub peer_public_key: Option<String>,
    pub endpoint: Option<String>,
    pub internal_ip: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnProvider {
    WireGuard,
    OpenVPN,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStatus {
    pub connected: bool,
    pub interface: Option<String>,
    pub internal_ip: Option<String>,
    pub peer_ip: Option<String>,
    pub latest_handshake: Option<i64>,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
    pub uptime_seconds: Option<u64>,
    pub provider: VpnProvider,
}

pub struct VpnManager {
    config: RwLock<VpnConfig>,
    status: RwLock<VpnStatus>,
}

impl VpnManager {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(VpnConfig {
                enabled: false,
                provider: VpnProvider::None,
                interface: "wg0".to_string(),
                allowed_ips: vec![],
                peer_public_key: None,
                endpoint: None,
                internal_ip: None,
            }),
            status: RwLock::new(VpnStatus {
                connected: false,
                interface: None,
                internal_ip: None,
                peer_ip: None,
                latest_handshake: None,
                transfer_rx: 0,
                transfer_tx: 0,
                uptime_seconds: None,
                provider: VpnProvider::None,
            }),
        }
    }

    pub fn configure(&self, config: VpnConfig) {
        *self.config.write() = config;
    }

    pub fn get_config(&self) -> VpnConfig {
        self.config.read().clone()
    }

    pub fn refresh_status(&self) -> VpnStatus {
        let config = self.config.read().clone();

        let (connected, status) = match config.provider {
            VpnProvider::WireGuard => self.check_wireguard(&config.interface),
            VpnProvider::OpenVPN => self.check_openvpn(&config.interface),
            VpnProvider::None => (
                false,
                VpnStatus {
                    connected: false,
                    interface: None,
                    internal_ip: None,
                    peer_ip: None,
                    latest_handshake: None,
                    transfer_rx: 0,
                    transfer_tx: 0,
                    uptime_seconds: None,
                    provider: VpnProvider::None,
                },
            ),
        };

        let mut new_status = status;
        new_status.connected = connected;

        *self.status.write() = new_status.clone();

        new_status
    }

    fn check_wireguard(&self, interface: &str) -> (bool, VpnStatus) {
        // Check if WireGuard interface exists
        let check = Command::new("wg").args(["show", interface]).output();

        match check {
            Ok(output) if output.status.success() => {
                let output_str = String::from_utf8_lossy(&output.stdout);

                let mut internal_ip = None;
                let mut peer_ip = None;
                let mut handshake = None;
                let mut rx: u64 = 0;
                let mut tx: u64 = 0;

                for line in output_str.lines() {
                    if line.starts_with("interface:") {
                        if let Some(ip) = line.split_whitespace().nth(1) {
                            internal_ip = Some(ip.to_string());
                        }
                    } else if line.contains("endpoint:") {
                        if let Some(ep) = line.split_whitespace().nth(1) {
                            peer_ip = Some(ep.to_string());
                        }
                    } else if line.contains("latest handshake:") {
                        if let Some(ts) = line.split_whitespace().last() {
                            if ts != "seconds" {
                                if let Ok(sec) = ts.parse::<i64>() {
                                    handshake = Some(chrono::Utc::now().timestamp() - sec);
                                }
                            }
                        }
                    } else if line.contains("transfer:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            if let Ok(r) = parts[1].parse::<u64>() {
                                rx = r;
                            }
                            if let Ok(t) = parts[3].parse::<u64>() {
                                tx = t;
                            }
                        }
                    }
                }

                (
                    true,
                    VpnStatus {
                        connected: true,
                        interface: Some(interface.to_string()),
                        internal_ip,
                        peer_ip,
                        latest_handshake: handshake,
                        transfer_rx: rx,
                        transfer_tx: tx,
                        uptime_seconds: handshake
                            .map(|h| (chrono::Utc::now().timestamp() - h) as u64),
                        provider: VpnProvider::WireGuard,
                    },
                )
            }
            _ => (
                false,
                VpnStatus {
                    connected: false,
                    interface: None,
                    internal_ip: None,
                    peer_ip: None,
                    latest_handshake: None,
                    transfer_rx: 0,
                    transfer_tx: 0,
                    uptime_seconds: None,
                    provider: VpnProvider::WireGuard,
                },
            ),
        }
    }

    fn check_openvpn(&self, interface: &str) -> (bool, VpnStatus) {
        // Check if OpenVPN is running
        let check = Command::new("pidof").arg("openvpn").output();

        let connected = check.map(|o| o.status.success()).unwrap_or(false);

        (
            connected,
            VpnStatus {
                connected,
                interface: if connected {
                    Some(interface.to_string())
                } else {
                    None
                },
                internal_ip: None,
                peer_ip: None,
                latest_handshake: None,
                transfer_rx: 0,
                transfer_tx: 0,
                uptime_seconds: None,
                provider: VpnProvider::OpenVPN,
            },
        )
    }

    pub fn get_status(&self) -> VpnStatus {
        self.status.read().clone()
    }

    pub fn connect(&self) -> Result<(), String> {
        let config = self.config.read().clone();

        match config.provider {
            VpnProvider::WireGuard => {
                // WireGuard needs to be configured via wg-quick
                tracing::info!("WireGuard connection requires pre-configuration");
                Ok(())
            }
            VpnProvider::OpenVPN => {
                tracing::info!("OpenVPN connection requires pre-configuration");
                Ok(())
            }
            VpnProvider::None => Err("No VPN provider configured".to_string()),
        }
    }

    pub fn disconnect(&self) -> Result<(), String> {
        let config = self.config.read().clone();

        match config.provider {
            VpnProvider::WireGuard => {
                let _ = Command::new("wg-quick")
                    .args(["down", &config.interface])
                    .output();
                Ok(())
            }
            VpnProvider::OpenVPN => {
                let _ = Command::new("pkill").args(["openvpn"]).output();
                Ok(())
            }
            VpnProvider::None => Ok(()),
        }
    }

    pub fn get_monitored_ips(&self) -> Vec<String> {
        let config = self.config.read().clone();
        config.allowed_ips.clone()
    }
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
}
