use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::anomaly::AnomalyDetector;
use crate::db::Database;
use crate::devices::DeviceManager;
use crate::sniffer::packet::{PacketInfo, Protocol};
use tokio::sync::broadcast;

pub struct Sniffer {
    interface: String,
}

impl Sniffer {
    pub fn new(interface: String) -> Self {
        Self { interface }
    }

    pub fn start(
        &self,
        packet_tx: broadcast::Sender<PacketInfo>,
        device_manager: Arc<DeviceManager>,
        anomaly_detector: Arc<AnomalyDetector>,
        database: Arc<Database>,
    ) {
        use pcap::{Capture, Device};

        let interface = self.interface.clone();

        std::thread::spawn(move || {
            tracing::info!("Starting sniffer on interface: {}", interface);

            let devices = match Device::list() {
                Ok(list) if !list.is_empty() => list,
                _ => {
                    tracing::error!("No network devices found");
                    return;
                }
            };

            let device_name = if interface.is_empty() {
                devices[0].name.clone()
            } else {
                interface
            };

            let device = devices
                .into_iter()
                .find(|d| d.name == device_name)
                .unwrap_or_else(|| Device::lookup().unwrap().unwrap());

            let cap = match Capture::from_device(device) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to open device: {}", e);
                    return;
                }
            };

            let mut active_cap = match cap.open() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to activate capture: {}", e);
                    return;
                }
            };

            tracing::info!("Capture opened successfully on {}", device_name);

            loop {
                match active_cap.next_packet() {
                    Ok(packet) => {
                        if let Some(info) = parse_packet(packet.data) {
                            let _ = packet_tx.send(info.clone());
                            device_manager.process_packet(&info);
                            anomaly_detector.analyze(&info);
                            let _ = database.save_packet(&info);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => {
                        tracing::warn!("Packet capture error: {}", e);
                    }
                }
            }
        });
    }
}

fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
    use etherparse::{NetSlice, SlicedPacket};

    let sliced = SlicedPacket::from_ethernet(data).ok()?;

    let (src_ip, dst_ip, src_port, dst_port, protocol, size) = match sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let src = IpAddr::V4(Ipv4Addr::from(ipv4.header().source()));
            let dst = IpAddr::V4(Ipv4Addr::from(ipv4.header().destination()));
            let proto = ipv4.header().protocol().0;

            let (sp, dp, proto_str) = match sliced.transport {
                Some(etherparse::TransportSlice::Tcp(tcp)) => (
                    Some(tcp.source_port()),
                    Some(tcp.destination_port()),
                    Protocol::Tcp,
                ),
                Some(etherparse::TransportSlice::Udp(udp)) => (
                    Some(udp.source_port()),
                    Some(udp.destination_port()),
                    Protocol::Udp,
                ),
                Some(etherparse::TransportSlice::Icmpv4(_)) => (None, None, Protocol::Icmp),
                _ => (None, None, Protocol::from(proto)),
            };

            let _header_len = 20u32;
            let payload_len = 20u32;
            (src, dst, sp, dp, proto_str, payload_len)
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let src = IpAddr::V6(Ipv6Addr::from(ipv6.header().source()));
            let dst = IpAddr::V6(Ipv6Addr::from(ipv6.header().destination()));
            let proto = ipv6.header().next_header().0;

            let (sp, dp, proto_str) = match sliced.transport {
                Some(etherparse::TransportSlice::Tcp(tcp)) => (
                    Some(tcp.source_port()),
                    Some(tcp.destination_port()),
                    Protocol::Tcp,
                ),
                Some(etherparse::TransportSlice::Udp(udp)) => (
                    Some(udp.source_port()),
                    Some(udp.destination_port()),
                    Protocol::Udp,
                ),
                Some(etherparse::TransportSlice::Icmpv6(_)) => (None, None, Protocol::Icmp),
                _ => (None, None, Protocol::from(proto)),
            };

            let _header_len = 40u32;
            let payload_len = 40u32;
            (src, dst, sp, dp, proto_str, payload_len)
        }
        _ => return None,
    };

    let src_mac = data.get(0..6).map(|m| {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    });
    let dst_mac = data.get(6..12).map(|m| {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    });

    Some(PacketInfo {
        timestamp: chrono::Utc::now().timestamp_millis(),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        size,
        src_mac,
        dst_mac,
    })
}

pub fn list_interfaces() -> Vec<String> {
    pcap::Device::list()
        .map(|devices| devices.iter().map(|d| d.name.clone()).collect())
        .unwrap_or_default()
}
