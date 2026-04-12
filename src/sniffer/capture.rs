use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::anomaly::AnomalyDetector;
use crate::db::Database;
use crate::devices::DeviceManager;
use crate::sniffer::packet::{PacketInfo, Protocol};
use bytes::BytesMut;
use crossbeam_channel::{bounded, Receiver, Sender};
use tokio::sync::broadcast;


// Packet pool for reducing allocations
#[derive(Clone)]
pub struct PacketPool {
    pool: Arc<parking_lot::Mutex<Vec<BytesMut>>>,
    buffer_size: usize,
}

impl PacketPool {
    pub fn new(buffer_size: usize, pool_size: usize) -> Self {
        let pool = Arc::new(parking_lot::Mutex::new(
            (0..pool_size)
                .map(|_| BytesMut::with_capacity(buffer_size))
                .collect(),
        ));
        Self { pool, buffer_size }
    }

    pub fn get(&self) -> BytesMut {
        let mut pool = self.pool.lock();
        pool.pop()
            .unwrap_or_else(|| BytesMut::with_capacity(self.buffer_size))
    }

    pub fn put(&self, mut buffer: BytesMut) {
        buffer.clear();
        let mut pool = self.pool.lock();
        if pool.len() < 1000 {
            // Limit pool size
            pool.push(buffer);
        }
    }
}

impl Default for PacketPool {
    fn default() -> Self {
        Self::new(2048, 100)
    }
}

#[inline]
fn format_mac(bytes: &[u8; 6]) -> String {
    let mut s = String::with_capacity(17);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push(std::char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(std::char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

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
        let num_workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .max(2);

        let (db_tx, db_rx) = std::sync::mpsc::sync_channel::<PacketInfo>(10_000);
        let (process_tx, process_rx): (Sender<PacketInfo>, Receiver<PacketInfo>) = bounded(10_000);

        let db_shutdown = shutdown.clone();
        let db = database.clone();
        std::thread::spawn(move || {
            let mut batch = Vec::with_capacity(256); // Increased initial capacity
            let mut last_flush = Instant::now();
            const FLUSH_INTERVAL_MS: u64 = 100; // More frequent flushing
            const MAX_BATCH_SIZE: usize = 512; // Larger max batch size

            loop {
                let timeout = if batch.is_empty() {
                    Duration::from_millis(FLUSH_INTERVAL_MS)
                } else {
                    // Adjust timeout based on batch size to prevent starvation
                    let elapsed = last_flush.elapsed();
                    if elapsed.as_millis() >= FLUSH_INTERVAL_MS as u128 {
                        Duration::from_millis(0) // Time to flush
                    } else {
                        Duration::from_millis(
                            FLUSH_INTERVAL_MS.saturating_sub(elapsed.as_millis() as u64),
                        )
                    }
                };

                if db_shutdown.load(Ordering::Relaxed) && db_rx.try_recv().is_err() {
                    if !batch.is_empty() {
                        db.save_packets_batch(&batch);
                    }
                    break;
                }

                match db_rx.recv_timeout(timeout) {
                    Ok(packet) => {
                        batch.push(packet);
                        // Process any additional available packets without blocking
                        while let Ok(p) = db_rx.try_recv() {
                            batch.push(p);
                            if batch.len() >= MAX_BATCH_SIZE {
                                break;
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }

                // Flush if we have enough packets or time has elapsed
                if !batch.is_empty()
                    && (batch.len() >= MAX_BATCH_SIZE
                        || last_flush.elapsed().as_millis() >= FLUSH_INTERVAL_MS as u128)
                {
                    db.save_packets_batch(&batch);
                    batch.clear();
                    last_flush = Instant::now();
                }
            }
            tracing::info!("Database writer thread stopped");
        });

        let worker_device_manager = device_manager.clone();
        let worker_anomaly_detector = anomaly_detector.clone();
        let worker_shutdown = shutdown.clone();
        for i in 0..num_workers {
            let rx = process_rx.clone();
            let dm = worker_device_manager.clone();
            let ad = worker_anomaly_detector.clone();
            let sd = worker_shutdown.clone();
            std::thread::spawn(move || {
                let mut batch = Vec::with_capacity(32);
                let mut last_process = Instant::now();
                const PROCESS_INTERVAL_MS: u64 = 10; // Process every 10ms max latency
                const MAX_BATCH_SIZE: usize = 128;

                loop {
                    let timeout = if batch.is_empty() {
                        Duration::from_millis(PROCESS_INTERVAL_MS)
                    } else {
                        // Adjust timeout based on batch size and time elapsed
                        let elapsed = last_process.elapsed();
                        if elapsed.as_millis() >= PROCESS_INTERVAL_MS as u128 {
                            Duration::from_millis(0) // Time to process
                        } else {
                            Duration::from_millis(
                                PROCESS_INTERVAL_MS.saturating_sub(elapsed.as_millis() as u64),
                            )
                        }
                    };

                    if sd.load(Ordering::Relaxed) {
                        // Process remaining packets before shutting down
                        if !batch.is_empty() {
                            for packet in batch.drain(..) {
                                dm.process_packet(&packet);
                                ad.analyze(&packet);
                            }
                        }
                        break;
                    }

                    match rx.recv_timeout(timeout) {
                        Ok(packet) => {
                            batch.push(packet);
                            // Process any additional available packets without blocking
                            while let Ok(p) = rx.try_recv() {
                                batch.push(p);
                                if batch.len() >= MAX_BATCH_SIZE {
                                    break;
                                }
                            }
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }

                    // Process batch if we have enough packets or time has elapsed
                    if !batch.is_empty()
                        && (batch.len() >= MAX_BATCH_SIZE
                            || last_process.elapsed().as_millis() >= PROCESS_INTERVAL_MS as u128)
                    {
                        // Use the new batch_analyze for parallel processing of the batch itself
                        ad.batch_analyze(&batch);
                        
                        for packet in batch.drain(..) {
                            dm.process_packet(&packet);
                        }
                        last_process = Instant::now();
                    }
                }
                tracing::debug!("Worker {} stopped", i);
            });
        }
        tracing::info!("Started {} packet processing workers", num_workers);

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
                if shutdown.load(Ordering::Relaxed) {
                    tracing::info!("Sniffer received shutdown signal");
                    break;
                }

                match active_cap.next_packet() {
                    Ok(packet) => {
                        if let Some(info) = parse_packet(packet.data) {
                            let _ = packet_tx.send(info.clone());
                            let _ = process_tx.try_send(info.clone());
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

    let (src_mac, dst_mac) = if data.len() >= 12 {
        let src_mac_bytes: &[u8; 6] = &data[0..6].try_into().unwrap();
        let dst_mac_bytes: &[u8; 6] = &data[6..12].try_into().unwrap();

        let src_mac = if src_mac_bytes.iter().any(|&b| b != 0) {
            Some(Cow::Owned(format_mac(src_mac_bytes)))
        } else {
            None
        };

        let dst_mac = if dst_mac_bytes.iter().any(|&b| b != 0) {
            Some(Cow::Owned(format_mac(dst_mac_bytes)))
        } else {
            None
        };

        (src_mac, dst_mac)
    } else {
        (None, None)
    };

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
