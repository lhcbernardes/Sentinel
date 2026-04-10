use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}

impl RiskLevel {
    pub fn from_open_ports(count: usize) -> Self {
        match count {
            0 => RiskLevel::Low,
            1..=2 => RiskLevel::Medium,
            3..=5 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub mac_address: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub manufacturer: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub open_ports: Vec<u16>,
    pub risk_level: RiskLevel,
    pub is_local: bool,
}

impl Device {
    pub fn new(mac: String) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            mac_address: mac,
            ip_address: None,
            hostname: None,
            manufacturer: None,
            first_seen: now,
            last_seen: now,
            packet_count: 0,
            total_bytes: 0,
            open_ports: Vec::new(),
            risk_level: RiskLevel::Low,
            is_local: false,
        }
    }

    pub fn update(&mut self, packet: &crate::sniffer::PacketInfo) {
        self.last_seen = packet.timestamp;
        self.packet_count += 1;
        self.total_bytes += packet.size as u64;

        if self.ip_address.is_none() {
            self.ip_address = Some(packet.src_ip.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_new() {
        let device = Device::new("00:11:22:33:44:55".to_string());
        assert_eq!(device.mac_address, "00:11:22:33:44:55");
        assert_eq!(device.risk_level, RiskLevel::Low);
        assert!(device.ip_address.is_none());
    }

    #[test]
    fn test_risk_level_from_open_ports() {
        assert_eq!(RiskLevel::from_open_ports(0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_open_ports(1), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_open_ports(3), RiskLevel::High);
        assert_eq!(RiskLevel::from_open_ports(10), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::Low), "low");
        assert_eq!(format!("{}", RiskLevel::Critical), "critical");
    }
}
