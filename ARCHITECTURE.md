# Architecture

## Overview

Sentinel-RS is a high-performance network security monitor written in Rust. It provides real-time packet capture, device discovery, anomaly detection, and integrated blocking capabilities.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Sentinel-RS                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐│
│  │ Sniffer │  │ Devices  │  │ Anomaly  │  │    Blocking       ││
│  │  Module │  │ Manager  │  │ Detector │  │ (DNS + Firewall)  ││
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘│
│       │             │             │                  │          │
│       └─────────────┴─────────────┴──────────────────┘          │
│                            │                                     │
│                    ┌───────┴───────┐                            │
│                    │   State Mgr   │                            │
│                    │  (ParkingLot) │                            │
│                    └───────┬───────┘                            │
│                            │                                     │
│       ┌────────────────────┼────────────────────┐               │
│       │                    │                    │               │
│  ┌────┴────┐         ┌─────┴─────┐        ┌─────┴─────┐        │
│  │   DB    │         │  Web API  │        │  Metrics  │        │
│  │SQLite   │         │   Axum    │        │Prometheus│        │
│  └─────────┘         └───────────┘        └───────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

## Core Modules

### 1. Sniffer Module (`src/sniffer/`)

Responsible for packet capture and analysis.

**Components:**
- `capture.rs` - PCAP capture setup and management
- `packet.rs` - Packet parsing (Ethernet, IP, TCP, UDP, ICMP)
- `netflow.rs` - NetFlow/IPFIX collection
- `dpi.rs` - Deep Packet Inspection

**Key Types:**
```rust
pub struct PacketInfo {
    pub timestamp: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub size: u32,
}
```

### 2. Devices Module (`src/devices/`)

Network device discovery and management.

**Components:**
- `device.rs` - Device representation with MAC, IP, vendor info
- `manager.rs` - Device tracking and state management
- `oui.rs` - OUI vendor database lookup

**Features:**
- Automatic device discovery via ARP/DHCP
- OUI-based vendor identification
- Device activity tracking

### 3. Anomaly Detection (`src/anomaly/`)

Real-time security threat detection.

**Components:**
- `detector.rs` - Main anomaly detection coordinator
- `portscan.rs` - Port scan detection algorithm
- `ml_detector.rs` - ML-based traffic anomaly detection
- `ransomware.rs` - Ransomware behavior detection

**Detection Types:**
- Port scanning (threshold-based)
- Traffic anomalies (statistical baseline)
- Ransomware indicators (entropy, behavioral)

### 4. Blocking System (`src/blocking/`)

Network blocking via DNS sinkhole and firewall.

**Components:**
- `dns_sinkhole.rs` - DNS server for blocking domains
- `firewall.rs` - Firewall integration (iptables/pf)
- `blocklist.rs` - Blocklist management
- `dns_over_https.rs` - DoH client for secure DNS
- `dns_over_tls.rs` - DoT client

**Blocklist Sources:**
- fabriziosalmi/blacklists (60+ lists)
- StevenBlack Hosts
- Firebog lists

### 5. Web Server (`src/web/`)

REST API and dashboard server.

**Endpoints:**
- `GET /` - Dashboard (HTMX + TailwindCSS)
- `GET /blocking` - Blocking management UI
- `GET /events` - Server-Sent Events stream
- `GET /api/v1/*` - REST API v1

**API Features:**
- JWT authentication
- Rate limiting
- CORS support

### 6. Metrics (`src/metrics/`)

Prometheus metrics export.

**Metrics:**
- `sentinel_packets_total` - Total packets captured
- `sentinel_devices_active` - Active device count
- `sentinel_blocked_total` - Total blocked items
- `sentinel_alerts_total` - Alert count by type

## Data Flow

```
Packet Capture → Parse → Analyze → Store/Alert/Block
     ↓              ↓        ↓        ↓
   PCAP        PacketInfo  Anomaly  SQLite
                           Detection  Alert
                                     Firewall
```

## Concurrency Model

- **Tokio** async runtime for I/O operations
- **ParkingLot** mutexes for internal state
- **Broadcast channels** for event distribution

```rust
// Event distribution example
let (alert_tx, _) = broadcast::channel(100);
sniffer.set_alert_sender(alert_tx);
```

## Database Schema

**Tables:**
- `devices` - Network devices
- `packets` - Captured packet metadata
- `alerts` - Security alerts
- `blocklist` - Blocked domains/IPs
- `traffic_stats` - Aggregated traffic stats

## Configuration

Environment variables control behavior:
- `INTERFACE` - Network interface for capture
- `SNIFFER_ENABLED` - Enable packet capture
- `DNS_ENABLED` - Enable DNS sinkhole
- `FIREWALL_ENABLED` - Enable firewall rules

## Security Considerations

1. **Privilege Separation** - Runs as root for packet capture
2. **Input Validation** - All network inputs validated
3. **Rate Limiting** - API endpoints protected
4. **Secure Defaults** - Strong password hashing (Argon2)

## Performance

- **Packet Processing**: ~100k packets/second
- **Memory Usage**: ~50MB baseline
- **Database**: SQLite with WAL mode
- **Concurrency**: Parallel processing per CPU core

## Extension Points

1. **Custom Analyzers** - Implement `Analyzer` trait
2. **Blocklist Sources** - Implement `BlocklistSource` trait
3. **Notification Handlers** - Implement `Notifier` trait

## Dependencies

| Crate | Purpose |
|-------|---------|
| tokio | Async runtime |
| axum | Web framework |
| pcap | Packet capture |
| etherparse | Packet parsing |
| rusqlite | Database |
| askama | Template engine |