use crate::devices::device::{Device, RiskLevel};
use crate::devices::oui::lookup_manufacturer;
use dashmap::DashMap;
use tokio::sync::broadcast;
use tracing::info;

use crate::sniffer::PacketInfo;

pub struct DeviceManager {
    devices: DashMap<String, Device>,
    alert_tx: broadcast::Sender<crate::anomaly::Alert>,
}

impl DeviceManager {
    pub fn new(alert_tx: broadcast::Sender<crate::anomaly::Alert>) -> Self {
        Self {
            devices: DashMap::with_capacity(256),
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
        let mac_key = if mac.bytes().all(|b| b.is_ascii_lowercase() || b == b':') {
            mac.to_string()
        } else {
            mac.to_lowercase()
        };

        let mut device = self.devices.entry(mac_key.clone()).or_insert_with(|| {
            let mut d = Device::new(mac_key.clone());
            d.manufacturer = lookup_manufacturer(&mac_key);

            let is_local = is_local_mac(&mac_key);
            d.is_local = is_local;

            if !is_local {
                let alert = crate::anomaly::Alert::new_device(mac_key.clone());
                let _ = self.alert_tx.send(alert);
            }

            info!("New device detected: {}", mac_key);
            d
        });

        // Mutate the device in-place
        device.update(packet);
        device.risk_level = RiskLevel::from_open_ports(device.open_ports.len());
    }

    pub fn get_all(&self) -> Vec<Device> {
        self.devices.iter().map(|r| r.value().clone()).collect()
    }

    pub fn get_by_mac(&self, mac: &str) -> Option<Device> {
        self.devices.get(mac).map(|r| r.value().clone())
    }

    pub fn add_open_port(&self, mac: &str, port: u16) {
        if let Some(mut device) = self.devices.get_mut(mac) {
            if !device.open_ports.contains(&port) {
                device.open_ports.push(port);
                device.risk_level = RiskLevel::from_open_ports(device.open_ports.len());
            }
        }
    }

    pub fn get_stats(&self) -> DeviceStats {
        let total = self.devices.len();
        let local_count = self.devices.iter().filter(|r| r.value().is_local).count();
        let high_risk = self
            .devices
            .iter()
            .filter(|r| r.value().risk_level == RiskLevel::High || r.value().risk_level == RiskLevel::Critical)
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
