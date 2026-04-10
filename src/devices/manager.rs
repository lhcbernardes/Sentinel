use crate::devices::device::{Device, RiskLevel};
use crate::devices::oui::lookup_manufacturer;
use parking_lot::RwLock;
use std::collections::HashMap;
use tokio::sync::broadcast;
use tracing::info;

use crate::sniffer::PacketInfo;

pub struct DeviceManager {
    devices: RwLock<HashMap<String, Device>>,
    alert_tx: broadcast::Sender<crate::anomaly::Alert>,
}

impl DeviceManager {
    pub fn new(alert_tx: broadcast::Sender<crate::anomaly::Alert>) -> Self {
        Self {
            devices: RwLock::new(HashMap::with_capacity(256)),
            alert_tx,
        }
    }

    pub fn process_packet(&self, packet: &PacketInfo) {
        if let Some(ref src_mac) = packet.src_mac {
            self.update_device(src_mac, packet);
        }

        if let Some(ref dst_mac) = packet.dst_mac {
            self.update_device(dst_mac, packet);
        }
    }

    fn update_device(&self, mac: &str, packet: &PacketInfo) {
        let mut devices = self.devices.write();

        let device = devices.entry(mac.to_string()).or_insert_with(|| {
            let mut d = Device::new(mac.to_string());
            d.manufacturer = lookup_manufacturer(mac);

            let is_local = is_local_mac(mac);
            d.is_local = is_local;

            if !is_local {
                let alert = crate::anomaly::Alert::new_device(mac.to_string());
                let _ = self.alert_tx.send(alert);
            }

            info!("New device detected: {}", mac);
            d
        });

        device.update(packet);
        device.risk_level = RiskLevel::from_open_ports(device.open_ports.len());
    }

    pub fn get_all(&self) -> Vec<Device> {
        self.devices.read().values().cloned().collect()
    }

    pub fn get_by_mac(&self, mac: &str) -> Option<Device> {
        self.devices.read().get(mac).cloned()
    }

    pub fn add_open_port(&self, mac: &str, port: u16) {
        let mut devices = self.devices.write();
        if let Some(device) = devices.get_mut(mac) {
            if !device.open_ports.contains(&port) {
                device.open_ports.push(port);
                device.risk_level = RiskLevel::from_open_ports(device.open_ports.len());
            }
        }
    }

    pub fn get_stats(&self) -> DeviceStats {
        let devices = self.devices.read();
        let total = devices.len();
        let local_count = devices.values().filter(|d| d.is_local).count();
        let high_risk = devices
            .values()
            .filter(|d| d.risk_level == RiskLevel::High || d.risk_level == RiskLevel::Critical)
            .count();

        DeviceStats {
            total_devices: total,
            local_devices: local_count,
            remote_devices: total - local_count,
            high_risk_count: high_risk,
        }
    }
}

fn is_local_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() < 2 {
        return false;
    }

    let first = u8::from_str_radix(parts[0], 16).unwrap_or(0);
    let _second = u8::from_str_radix(parts[1], 16).unwrap_or(0);

    (first & 0x02) != 0
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceStats {
    pub total_devices: usize,
    pub local_devices: usize,
    pub remote_devices: usize,
    pub high_risk_count: usize,
}
