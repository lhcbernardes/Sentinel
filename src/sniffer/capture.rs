use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
        shutdown: Arc<AtomicBool>,
    ) {
        use pcap::{Capture, Device};

        let interface = self.interface.clone();

        // Channel to decouple packet capture from database I/O
        let (db_tx, db_rx) = std::sync::mpsc::sync_channel::<PacketInfo>(10_000);

        // Database writer thread: batches inserts to reduce lock contention
        let db_shutdown = shutdown.clone();
        let db = database.clone();
        std::thread::spawn(move || {
            let mut batch = Vec::with_capacity(100);
            loop {
                if db_shutdown.load(Ordering::Relaxed) && db_rx.try_recv().is_err() {
                    // Flush remaining
                    if !batch.is_empty() {
                        db.save_packets_batch(&batch);
                    }
                    break;
                }

                match db_rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(packet) => {
                        batch.push(packet);
                        // Drain any buffered packets without blocking
                        while let Ok(p) = db_rx.try_recv() {
                            batch.push(p);
                            if batch.len() >= 100 {
                                break;
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }

                if !batch.is_empty() {
                    db.save_packets_batch(&batch);
                    batch.clear();
                }
            }
            tracing::info!("Database writer thread stopped");
        });

        // Packet capture thread
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

            let device = match devices.into_iter().find(|d| d.name == device_name) {
                Some(d) => d,
                None => match Device::lookup() {
                    Ok(Some(d)) => {
                        tracing::warn!(
                            "Interface '{}' not found, falling back to default: {}",
                            device_name,
                            d.name
                        );
                        d
                    }
                    Ok(None) => {
                        tracing::error!("No default network device available");
                        return;
                    }
                    Err(e) => {
                        tracing::error!("Failed to lookup default device: {}", e);
                        return;
                    }
                },
            };

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
                // Check for shutdown signal
                if shutdown.load(Ordering::Relaxed) {
                    tracing::info!("Sniffer received shutdown signal");
                    break;
                }

                match active_cap.next_packet() {
                    Ok(packet) => {
                        if let Some(info) = parse_packet(packet.data) {
                            let _ = packet_tx.send(info.clone());
                            device_manager.process_packet(&info);
                            anomaly_detector.analyze(&info);
                            // Send to DB writer thread (non-blocking: drop if full)
                            let _ = db_tx.try_send(info);
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
            tracing::info!("Sniffer thread stopped");
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

            // Use actual total length from IP header instead of hardcoded value
            let total_len = ipv4.header().total_len() as u32;
            (src, dst, sp, dp, proto_str, total_len)
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

            // IPv6: 40-byte header + payload_length
            let total_len = 40 + ipv6.header().payload_length() as u32;
            (src, dst, sp, dp, proto_str, total_len)
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
