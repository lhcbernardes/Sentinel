use crate::devices::device::{Device, RiskLevel};
use crate::devices::oui::lookup_manufacturer;
use dashmap::DashMap;
use tokio::sync::broadcast;
use tracing::{info, warn, debug};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::sniffer::PacketInfo;

pub struct DeviceManager {
    devices: DashMap<String, Device>,
    dirty: DashMap<String, bool>,
    alert_tx: broadcast::Sender<crate::anomaly::Alert>,
}

impl DeviceManager {
    pub fn new(alert_tx: broadcast::Sender<crate::anomaly::Alert>) -> Self {
        Self {
            devices: DashMap::with_capacity(256),
            dirty: DashMap::with_capacity(256),
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
        
        // Mark as dirty for sync
        self.dirty.insert(mac_key, true);
    }

    pub fn start_sync_task(self: Arc<Self>, database: Arc<crate::db::Database>) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30)); 
            const TTL: i64 = 300_000; // 5 minutes in milliseconds

            loop {
                interval.tick().await;
                let now = chrono::Utc::now().timestamp_millis();
                
                // 1. Sync dirty devices to DB
                let mut dirty_macs = Vec::new();
                for r in manager.dirty.iter() {
                    if *r.value() {
                        dirty_macs.push(r.key().clone());
                    }
                }
                manager.dirty.clear();

                if !dirty_macs.is_empty() {
                    let mut devices_to_sync = Vec::with_capacity(dirty_macs.len());
                    for mac in &dirty_macs {
                        if let Some(device) = manager.devices.get(mac) {
                            devices_to_sync.push(device.clone());
                        }
                    }

                    if !devices_to_sync.is_empty() {
                        if let Err(e) = database.save_devices_batch(&devices_to_sync) {
                            warn!("Failed to sync devices to database: {}", e);
                            // Re-mark as dirty if failed
                            for mac in dirty_macs {
                                manager.dirty.insert(mac, true);
                            }
                        } else {
                            debug!("Synced {} dirty devices to database", devices_to_sync.len());
                        }
                    }
                }

                // 2. Cache eviction (TTL)
                let mut to_evict = Vec::new();
                for r in manager.devices.iter() {
                    if now - r.value().last_seen > TTL {
                        to_evict.push(r.key().clone());
                    }
                }

                for mac in to_evict {
                    debug!("Evicting inactive device from cache: {}", mac);
                    manager.devices.remove(&mac);
                }
            }
        });
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
                self.dirty.insert(mac.to_string(), true);
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
            remote_devices: if total > local_count { total - local_count } else { 0 },
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
    (first & 0x02) != 0
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceStats {
    pub total_devices: usize,
    pub local_devices: usize,
    pub remote_devices: usize,
    pub high_risk_count: usize,
}
