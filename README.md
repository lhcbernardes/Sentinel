# Sentinel-RS 🛡️

High-performance Local Network Security Monitor written in Rust.

## Features

### 🔍 Network Monitoring
- **Packet Sniffer**: Real-time packet capture using pcap
- **Device Discovery**: Network device detection via MAC and OUI
- **Traffic Analysis**: TCP, UDP, ICMP protocols
- **DHCP Monitoring**: DHCP lease tracking

### 🚨 Anomaly Detection
- **Port Scan Detection**: Identifies suspicious port scans
- **Ransomware Detection**: Entropy analysis and behavioral monitoring
- **Real-time Alerts**: SSE notifications for security events

### 🛡️ Blocking System
- **DNS Sinkhole**: Malicious domain blocking via DNS
- **Firewall**: Integration with iptables (Linux) / pf (macOS)
- **Blocklists**: Multiple sources:
  - fabriziosalmi/blacklists (60+ lists)
  - StevenBlack Hosts
  - Firebog lists
  - Malware domain lists

### 🌐 Web Interface
- **Real-time Dashboard**: HTMX + TailwindCSS
- **Event Streaming**: Live updates via Server-Sent Events
- **Blocking Management**: Add/remove domains and IPs

### 💾 Persistence
- **SQLite**: Local data storage
- **Backup/Restore**: Complete backup system

### 📊 Observability
- **Prometheus Metrics**: `/metrics` endpoint
- **Grafana Integration**: Pre-configured dashboards
- **Alertmanager**: Alert routing and notification

## Requirements

- Rust 1.70+
- macOS or Linux
- Root privileges for packet capture and DNS

## Quick Start

```bash
# Clone the project
git clone https://github.com/lhcbernardes/Sentinel.git
cd Sentinel

# Build
cargo build

# Run (without sniffer - for testing)
SNIFFER_ENABLED=false cargo run

# Run with sudo (full features)
sudo cargo run
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INTERFACE` | auto | Network interface |
| `DB_PATH` | data/sentinel.db | SQLite database path |
| `SNIFFER_ENABLED` | true | Enable packet sniffer |
| `DNS_ENABLED` | false | Enable DNS sinkhole |
| `DNS_PORT` | 53 | DNS sinkhole port |
| `FIREWALL_ENABLED` | true | Enable firewall management |
| `LISTEN_ADDR` | 0.0.0.0:8080 | Server listen address |

## Network Setup

### Option 1: Router DNS (Recommended)
1. Find machine IP: `ifconfig` or `ip addr`
2. Access router settings
3. Set primary DNS to Sentinel-RS machine IP

### Option 2: DNS Sinkhole
```bash
sudo DNS_ENABLED=true DNS_PORT=53 cargo run
```

## Access

- **Dashboard**: http://localhost:8080
- **Blocking**: http://localhost:8080/blocking
- **API Events**: http://localhost:8080/events

## Default Credentials

- **Username**: admin
- **Password**: admin123

⚠️ Change password in production!

## Docker

```bash
docker-compose up -d
```

Services: Sentinel-RS, Prometheus, Grafana, Alertmanager

## Tech Stack

- **Backend**: Rust, Axum, Tokio
- **Database**: SQLite (rusqlite)
- **Frontend**: HTML, TailwindCSS, HTMX
- **Packet Capture**: pcap, etherparse

## License

MIT License
