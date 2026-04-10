<div align="center">
  <h1>Sentinel-RS 🛡️</h1>
  
  <p>
    <strong>High-performance, Next-Gen Local Network Security Monitor written in Rust.</strong>
  </p>

  <p>
    <a href="https://github.com/lhcbernardes/Sentinel"><img src="https://img.shields.io/badge/rust-1.70%2B-EF4A25?style=for-the-badge&logo=rust&logoColor=white" alt="Rust Version" /></a>
    <a href="https://github.com/lhcbernardes/Sentinel"><img src="https://img.shields.io/badge/framework-Axum-000000?style=for-the-badge" alt="Axum Framework" /></a>
    <a href="https://github.com/lhcbernardes/Sentinel"><img src="https://img.shields.io/badge/UI-TailwindCSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind CSS" /></a>
    <a href="https://github.com/lhcbernardes/Sentinel"><img src="https://img.shields.io/badge/security-JWT%20(HS256)-blue?style=for-the-badge&logo=jsonwebtokens" alt="JWT Secured" /></a>
    <a href="https://github.com/lhcbernardes/Sentinel/blob/main/LICENSE"><img src="https://img.shields.io/github/license/lhcbernardes/Sentinel?style=for-the-badge" alt="License" /></a>
  </p>
</div>

---

## 📌 Overview

Sentinel-RS is a lightweight but powerful localized network monitor that secures your connection against ransomware, port scans, malware, and trackers. 

Engineered entirely in **Rust**, it acts as a firewall manager, real-time packer sniffer, and robust DNS sinkhole—featuring a **Premium Glassmorphic Dashboard** complete with immersive neon charts and live event streaming.

---

## ✨ Key Features

### 🔍 Network Monitoring
- **Packet Sniffer**: Real-time packet capture via low-level `pcap`.
- **Intelligent Discovery**: Network device fingerprinting via MAC and OUI resolution.
- **Deep Traffic Analysis**: Protocol tracking for TCP, UDP, and ICMP.
- **DHCP Surveillance**: Tracks active allocations and leases locally.

### 🚨 Anomaly Detection
- **Port Scan Detection**: Actively hunts down internal and external aggressive port sweeps.
- **Ransomware Deterrent**: Employs heuristic entropy data analysis for detecting cryptolocker behaviors.
- **Live Visual Alerts**: Flashing UI glow alerts streamed smoothly via non-blocking SSE (Server-Sent Events).

### 🛡️ Active Prevention & Blocking
- **DNS Sinkhole Engine**: Redirects queries for known malicious hostnames instantaneously.
- **OS-Layer Firewall Integration**: Hooks dynamically to `pf` (macOS) and `iptables` (Linux).
- **Aggregated Threat Intel**:
  - Pulls actively from fabriziosalmi/blacklists (+60 lists)
  - StevenBlack, Firebog, and comprehensive Malware Domain lists.

### 🌐 Cybersecurity Web Interface
- **Glassmorphism UI**: Beautiful, tactile front-end featuring backdrop-blurs, neon glow accents (`Inter` fonts), powered by **Tailwind CSS**.
- **Askama Templating Engine**: Fully typed, lightning-fast HTML rendering natively from Rust structs.
- **Live Dashboard Tracker**: Premium Chart.js instances designed without visual clutter, showing real-time metrics.

---

## 🚀 Quick Start

### 1. Requirements
- **Rust 1.70+** installed
- macOS or Linux OS natively supported
- Root (Sudo) privileges required to run network capture (bpf/pcap).

### 2. Environment Setup
Clone the repository and prepare your private variables:
```bash
git clone https://github.com/lhcbernardes/Sentinel.git
cd Sentinel
cp .env.example .env
```
Make sure you replace `SENTINEL_JWT_SECRET` and `SENTINEL_ADMIN_PASSWORD` in your `.env` for production security!

### 3. Build & Run
```bash
# Build binary
cargo build

# Run application locally with full Network Privileges
sudo -E cargo run
```
*Note: Due to libpcap hardware hooks, if you start Sentinel-RS without `sudo`, the web interface will continue running for demo purposes, but the packet sniffer core will silently log a permission denied error without panicking.*

---

## ⚙️ Configuration Variables

| Variable | Default (Fallback) | Description |
|----------|---------|-------------|
| `INTERFACE` | `auto` | Network interface to bind pcap to |
| `DB_PATH` | `data/sentinel.db` | Directory path pointing to SQLite storage |
| `LISTEN_ADDR` | `0.0.0.0:8080` | Port and address serving Axum HTTP server |
| `SENTINEL_JWT_SECRET` | *Random Per Session* | Strong Base64 secret enforcing HS256 JWT tokens |
| `SENTINEL_ADMIN_PASSWORD` | `admin123` | Master password for RBAC Administrator Access |
| `SNIFFER_ENABLED` | `true` | Start backend packet tracking |
| `FIREWALL_ENABLED`| `true` | Manipulate OS Firewall tables (iptables/pf) |
| `DNS_ENABLED` | `false` | Turn on internal DNS resolution interception |

---

## 📊 Deployment & Observability

### Docker Deployment
```bash
# Deploys Sentinel, Prometheus, Alertmanager, and Grafana Stack
docker-compose up -d
```

### Metrics
- Application natively outputs metrics at `/metrics`.
- Prometheus and Grafana instances hook into telemetry for comprehensive analytics charting.

---

## 🛠 Tech Stack

- **Backend Logic**: Rust, Tokio (Async), Axum.
- **Datastore Handling**: SQLite (`rusqlite`).
- **Templating**: Askama.
- **Network Stack**: `pcap`, `etherparse`.
- **Frontend Architecture**: Tailwind CSS 3.x, HTMX, AlpineJS (Animations/Transitions), Chart.js.

---

## 📝 License

Distributed under the **MIT License**. See `LICENSE` for more information.
