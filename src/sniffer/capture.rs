use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::anomaly::AnomalyDetector;
use crate::db::Database;
use crate::devices::DeviceManager;
use crate::sniffer::packet::PacketInfo;
use tokio::sync::broadcast;
use crate::sniffer::pool::{PacketPool, PooledPacketInfo};


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

        // Initialize PacketPool (shared across capture and workers)
        let pool = Arc::new(PacketPool::new(1000));

        // Use tokio channels for async actor-like communication
        let (db_tx, mut db_rx) = tokio::sync::mpsc::channel::<PacketInfo>(10_000);
        // Note: process_rx is used by workers. Since we have multiple workers, 
        // we can use a single receiver if we wrap it in a Mutex, or use a broadcast channel.
        // But for high-throughput packet processing, we'll use a single MPSC for all workers
        // and have them pull from it.
        let (worker_tx, worker_rx) = tokio::sync::mpsc::channel::<PooledPacketInfo>(10_000);
        let worker_rx = Arc::new(tokio::sync::Mutex::new(worker_rx));

        // Database Actor Task
        let db_shutdown = shutdown.clone();
        let db = database.clone();
        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(512);
            const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

            loop {
                if db_shutdown.load(Ordering::Relaxed) && db_rx.is_empty() {
                    if !batch.is_empty() {
                        db.save_packets_batch(&batch);
                    }
                    break;
                }

                tokio::select! {
                    Some(packet) = db_rx.recv() => {
                        batch.push(packet);
                        if batch.len() >= 512 {
                            db.save_packets_batch(&batch);
                            batch.clear();
                        }
                    }
                    _ = tokio::time::sleep(FLUSH_INTERVAL) => {
                        if !batch.is_empty() {
                            db.save_packets_batch(&batch);
                            batch.clear();
                        }
                    }
                }
            }
            tracing::info!("Database writer actor stopped");
        });

        // Worker Actor Tasks
        let worker_device_manager = device_manager.clone();
        let worker_anomaly_detector = anomaly_detector.clone();
        let worker_shutdown = shutdown.clone();
        
        for i in 0..num_workers {
            let rx = worker_rx.clone();
            let dm = worker_device_manager.clone();
            let ad = worker_anomaly_detector.clone();
            let sd = worker_shutdown.clone();
            let p_tx = packet_tx.clone();
            let d_tx = db_tx.clone();
            
            tokio::spawn(async move {
                let mut batch = Vec::with_capacity(128);
                const PROCESS_INTERVAL: Duration = Duration::from_millis(10);

                loop {
                    if sd.load(Ordering::Relaxed) && rx.lock().await.is_empty() {
                        break;
                    }

                    let mut rx_lock = rx.lock().await;
                    match tokio::time::timeout(PROCESS_INTERVAL, rx_lock.recv()).await {
                        Ok(Some(pooled)) => {
                            let info = pooled.into_owned();
                            // Broadcast to UI
                            let _ = p_tx.send(info.clone());
                            // Send to DB
                            let _ = d_tx.try_send(info.clone());
                            
                            batch.push(info);
                            
                            if batch.len() >= 128 {
                                ad.batch_analyze(&batch);
                                for p in batch.drain(..) {
                                    dm.process_packet(&p);
                                }
                                batch.clear();
                            }
                        }
                        _ => {
                            if !batch.is_empty() {
                                ad.batch_analyze(&batch);
                                for p in batch.drain(..) {
                                    dm.process_packet(&p);
                                }
                                batch.clear();
                            }
                        }
                    }
                    drop(rx_lock);
                    tokio::task::yield_now().await;
                }
                tracing::debug!("Worker actor {} stopped", i);
            });
        }
        tracing::info!("Started {} packet processing worker actors", num_workers);

        // Capture Actor Task (Blocking)
        let capture_shutdown = shutdown.clone();
        let capture_interface = interface.clone();
        let capture_pool = pool.clone();
        let capture_worker_tx = worker_tx.clone();

        tokio::task::spawn_blocking(move || {
            tracing::info!("Starting sniffer on interface: {}", capture_interface);

            let devices = match Device::list() {
                Ok(list) if !list.is_empty() => list,
                _ => {
                    tracing::error!("No network devices found");
                    return;
                }
            };

            let device_name = if capture_interface.is_empty() {
                devices[0].name.clone()
            } else {
                capture_interface
            };

            let device = match devices.into_iter().find(|d| d.name == device_name) {
                Some(d) => d,
                None => match Device::lookup() {
                    Ok(Some(d)) => {
                        tracing::warn!("Interface '{}' not found, falling back to default: {}", device_name, d.name);
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
                if capture_shutdown.load(Ordering::Relaxed) {
                    tracing::info!("Sniffer received shutdown signal");
                    break;
                }

                match active_cap.next_packet() {
                    Ok(packet) => {
                        if let Some(pooled) = parse_packet_pooled(packet.data, capture_pool.clone()) {
                            let _ = capture_worker_tx.try_send(pooled);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => {
                        tracing::warn!("Packet capture error: {}", e);
                    }
                }
            }
            tracing::info!("Sniffer capture task stopped");
        });
    }
}

fn parse_packet_pooled(data: &[u8], pool: Arc<PacketPool>) -> Option<PooledPacketInfo> {
    use etherparse::{NetSlice, SlicedPacket};

    let sliced = SlicedPacket::from_ethernet(data).ok()?;
    let mut pooled = PooledPacketInfo::new(pool);
    let now = chrono::Utc::now().timestamp_millis();

    match sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            pooled.populate(now, ipv4.header().total_len() as u32, ipv4.header().protocol().0);
            pooled.set_ipv4_src(ipv4.header().source());
            pooled.set_ipv4_dst(ipv4.header().destination());

            if let Some(transport) = sliced.transport {
                match transport {
                    etherparse::TransportSlice::Tcp(tcp) => {
                        pooled.set_ports(Some(tcp.source_port()), Some(tcp.destination_port()));
                        pooled.set_protocol(6);
                    }
                    etherparse::TransportSlice::Udp(udp) => {
                        pooled.set_ports(Some(udp.source_port()), Some(udp.destination_port()));
                        pooled.set_protocol(17);
                    }
                    etherparse::TransportSlice::Icmpv4(_) => {
                        pooled.set_protocol(1);
                    }
                    _ => {}
                }
            }
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            pooled.populate(now, 40 + ipv6.header().payload_length() as u32, ipv6.header().next_header().0);
            pooled.set_ipv6_src(ipv6.header().source());
            pooled.set_ipv6_dst(ipv6.header().destination());

            if let Some(transport) = sliced.transport {
                match transport {
                    etherparse::TransportSlice::Tcp(tcp) => {
                        pooled.set_ports(Some(tcp.source_port()), Some(tcp.destination_port()));
                        pooled.set_protocol(6);
                    }
                    etherparse::TransportSlice::Udp(udp) => {
                        pooled.set_ports(Some(udp.source_port()), Some(udp.destination_port()));
                        pooled.set_protocol(17);
                    }
                    etherparse::TransportSlice::Icmpv6(_) => {
                        pooled.set_protocol(58); // ICMPv6
                    }
                    _ => {}
                }
            }
        }
        _ => return None,
    }

    if data.len() >= 12 {
        let src_mac_bytes: [u8; 6] = data[0..6].try_into().unwrap_or([0; 6]);
        let dst_mac_bytes: [u8; 6] = data[6..12].try_into().unwrap_or([0; 6]);

        if src_mac_bytes.iter().any(|&b| b != 0) {
            pooled.set_mac_src(src_mac_bytes);
        }
        if dst_mac_bytes.iter().any(|&b| b != 0) {
            pooled.set_mac_dst(dst_mac_bytes);
        }
    }

    Some(pooled)
}

pub fn list_interfaces() -> Vec<String> {
    pcap::Device::list()
        .map(|devices| devices.iter().map(|d| d.name.clone()).collect())
        .unwrap_or_default()
}
