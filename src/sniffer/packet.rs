use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub size: u32,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<u8> for Protocol {
    fn from(v: u8) -> Self {
        match v {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            _ => Protocol::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PacketInfo, Protocol};
    use std::net::IpAddr;

    #[test]
    fn test_packet_info_creation() {
        let packet = PacketInfo {
            timestamp: 1234567890,
            src_ip: IpAddr::from([192, 168, 1, 100]),
            dst_ip: IpAddr::from([192, 168, 1, 1]),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: Protocol::Tcp,
            size: 1500,
            src_mac: Some("00:11:22:33:44:55".to_string()),
            dst_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
        };

        assert_eq!(packet.protocol, Protocol::Tcp);
        assert_eq!(packet.size, 1500);
    }

    #[test]
    fn test_protocol_from_u8() {
        assert_eq!(Protocol::from(6), Protocol::Tcp);
        assert_eq!(Protocol::from(17), Protocol::Udp);
        assert_eq!(Protocol::from(1), Protocol::Icmp);
        assert_eq!(Protocol::from(99), Protocol::Unknown);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Tcp), "TCP");
        assert_eq!(format!("{}", Protocol::Udp), "UDP");
        assert_eq!(format!("{}", Protocol::Icmp), "ICMP");
        assert_eq!(format!("{}", Protocol::Unknown), "Unknown");
    }
}
