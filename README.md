<div align="center">
  <h1>Sentinel-RS 🛡️</h1>
   
  <p>
    <strong>High-performance, Next-Gen Local Network Security Monitor written in Rust.</strong>
  </p>

  <p>
    <a href="https://github.com/lhcbernardes/Sentinel/actions"><img src="https://img.shields.io/github/actions/workflow/status/lhcbernardes/Sentinel/ci.yml?style=for-the-badge&logo=github-actions" alt="CI Status" /></a>
    <a href="https://crates.io/crates/sentinel-rs"><img src="https://img.shields.io/crates/v/sentinel-rs?style=for-the-badge" alt="crates.io" /></a>
    <img src="https://img.shields.io/github/languages/top/lhcbernardes/Sentinel?style=for-the-badge&logo=rust&logoColor=white" alt="Top Language" />
    <a href="https://github.com/lhcbernardes/Sentinel/blob/main/LICENSE"><img src="https://img.shields.io/github/license/lhcbernardes/Sentinel?style=for-the-badge" alt="License" /></a>
  </p>

  <p>
    <a href="https://github.com/lhcbernardes/Sentinel/stars"><img src="https://img.shields.io/github/stars/lhcbernardes/Sentinel?style=for-the-badge&color=gold" alt="GitHub Stars" /></a>
    <a href="https://github.com/lhcbernardes/Sentinel/network/members"><img src="https://img.shields.io/github/forks/lhcbernardes/Sentinel?style=for-the-badge&color=blue" alt="GitHub Forks" /></a>
    <a href="https://github.com/lhcbernardes/Sentinel/issues"><img src="https://img.shields.io/github/issues/lhcbernardes/Sentinel?style=for-the-badge&color=red" alt="GitHub Issues" /></a>
    <a href="https://github.com/lhcbernardes/Sentinel/pulls"><img src="https://img.shields.io/github/issues-pr/lhcbernardes/Sentinel?style=for-the-badge&color=orange" alt="GitHub PRs" /></a>
  </p>

  <p>
    <a href="https://github.com/lhcbernardes/Sentinel"><img src="https://img.shields.io/badge/framework-Axum-000000?style=for-the-badge" alt="Axum Framework" /></a>
    <a href="https://github.com/lhcbernardes/Sentinel"><img src="https://img.shields.io/badge/UI-TailwindCSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind CSS" /></a>
    <a href="https://github.com/lhcbernardes/Sentinel"><img src="https://img.shields.io/badge/security-JWT%20(HS256)-blue?style=for-the-badge&logo=jsonwebtokens" alt="JWT Secured" /></a>
    <img src="https://img.shields.io/badge/SSE-Live%20Events-FF6B6B?style=for-the-badge" alt="Server-Sent Events" />
  </p>

  <p>
    <img src="https://img.shields.io/badge/Maintained%3F-Yes-green?style=for-the-badge" alt="Maintained" />
    <a href="https://github.com/lhcbernardes/Sentinel/graphs/contributors"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge" alt="PRs Welcome" /></a>
    <img src="https://img.shields.io/badge/rust-1.70%2B-EF4A25?style=for-the-badge&logo=rust&logoColor=white" alt="Rust Version" />
  </p>
</div>

---

## 📌 Overview

Sentinel-RS is a lightweight but powerful localized network monitor that secures your connection against ransomware, port scans, malware, and trackers. 

Engineered entirely in **Rust**, it acts as a firewall manager, real-time packet sniffer, and robust DNS sinkhole—featuring a **Premium Glassmorphic Dashboard** complete with immersive neon charts and live event streaming.

---

## ✨ Key Features

### 🔍 Network Monitoring
- **Packet Sniffer**: Real-time packet capture via low-level `pcap` with parallel processing.
- **Intelligent Discovery**: Network device fingerprinting via MAC and OUI resolution.
- **Deep Traffic Analysis**: Protocol tracking for TCP, UDP, and ICMP.
- **DHCP Surveillance**: Tracks active allocations and leases locally.

### 🚨 Anomaly Detection
- **Port Scan Detection**: Actively hunts down internal and external aggressive port sweeps.
- **Ransomware Deterrent**: Employs heuristic entropy data analysis for detecting cryptolocker behaviors.
- **Live Visual Alerts**: Flashing UI glow alerts streamed smoothly via non-blocking SSE (Server-Sent Events).

### 🛡️ Active Prevention & Blocking
- **DNS Sinkhole Engine**: Redirects queries for known malicious hostnames instantaneously.
- **OS-Layer Firewall Integration**: Hooks dynamically to `pf` (macOS) and `iptables` (Linux) with non-blocking commands.
- **Aggregated Threat Intel**:
  - Pulls actively from fabriziosalmi/blacklists (+60 lists)
  - StevenBlack, Firebog, and comprehensive Malware Domain lists.

### 🌐 Cybersecurity Web Interface
- **Glassmorphism UI**: Beautiful, tactile front-end featuring backdrop-blurs, neon glow accents (`Inter` fonts), powered by **Tailwind CSS**.
- **Askama Templating Engine**: Fully typed, lightning-fast HTML rendering natively from Rust structs.
- **Live Dashboard Tracker**: Premium Chart.js instances designed without visual clutter, showing real-time metrics.
- **Multi-language Support**: English, Portuguese, and Spanish translations built-in.

---

## ⚡ Performance Optimizations

Sentinel-RS is engineered for high throughput with the following parallelization strategies:

| Component | Optimization | Benefit |
|-----------|-------------|---------|
| **Blocklist Updates** | Parallel downloads with semaphore (10 concurrent) | ~10x faster list updates |
| **Network Scanner** | Parallel ping sweep with Rayon | 254 hosts in seconds |
| **Packet Processing** | Worker pool (N cores) | Linear scaling with CPU cores |
| **Firewall Commands** | Background thread dispatch | Non-blocking iptables/pfctl |
| **Database** | Multi-row INSERT batching + WAL mode | 100x faster packet storage |
| **Data Structures** | Pre-allocated HashMaps/HashSets | Zero reallocation overhead |

---

## 🚀 Quick Start

### 1. Requirements
- **Rust 1.70+** installed
- macOS or Linux OS natively supported
- Root (Sudo) privileges required to run network capture (bpf/pcap).

### 2. Environment Setup
Clone the repository and prepare your private variables:
```bash
git clone https://github.com/sentinel-rs/sentinel-rs.git
cd sentinel-rs
cp .env.example .env
```
Make sure to replace `SENTINEL_JWT_SECRET` and `SENTINEL_ADMIN_PASSWORD` in your `.env` for production security!

> **Default credentials:** `admin` / `Sentinel@2024`
> Password requirements: min 8 chars, 1 uppercase, 1 digit, 1 special character.

### 3. Build & Run

#### macOS
```bash
# Identificar interface de rede
networksetup -listallhardwareports

# Build
cargo build

# Run (sudo necessário para captura de pacotes)
sudo -E INTERFACE=en0 cargo run

# Ou usar script automático
./run.sh mac
```

#### Linux
```bash
# Identificar interface de rede
ip link show

# Instalar dependências (Debian/Ubuntu)
sudo apt install libpcap-dev

# Build
cargo build

# Run (sudo necessário para captura de pacotes)
sudo -E INTERFACE=eth0 cargo run

# Ou usar script automático
./run.sh linux
```

#### Windows
```bash
# Instalar Npcap: https://npcap.com/dist/npcap.exe
# Escolha "Install Npcap 1.0" (sem "Install WinPcap API Compatible" se não precisar)

# Identificar interface (Execute como Administrador)
ipconfig

# Setar variável de ambiente para usar Npcap
set INTERFACE="Ethernet"

# Build
cargo build

# Run (executar como Administrador)
set INTERFACE="Ethernet" && cargo run

# Ou usar script automático
run.bat
```

#### ⚠️ Notas Importantes
- **Sem sudo/admin**: O servidor web continua funcionando, mas o sniffer de pacotes mostrará erro de permissão.
- **Interface padrão**: macOS usa `en0`, Linux usa `eth0`, Windows usa o nome do adaptador.
- **Credenciais padrão**: `admin` / `Sentinel@2024`

---

## ⚙️ Configuration Variables

| Variable | Default (Fallback) | Description |
|----------|---------|-------------|
| `INTERFACE` | `auto` | Network interface to bind pcap to |
| `DB_PATH` | `data/sentinel.db` | Directory path pointing to SQLite storage |
| `LISTEN_ADDR` | `0.0.0.0:8080` | Port and address serving Axum HTTP server |
| `SENTINEL_JWT_SECRET` | *Random Per Session* | Strong Base64 secret enforcing HS256 JWT tokens |
| `SENTINEL_ADMIN_PASSWORD` | `Sentinel@2024` | Master password for RBAC Administrator Access (min 8 chars, 1 uppercase, 1 digit, 1 special) |
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
- **Datastore Handling**: SQLite (`rusqlite`) with WAL mode.
- **Templating**: Askama.
- **Network Stack**: `pcap`, `etherparse`.
- **Concurrency**: `rayon` (data parallelism), `crossbeam-channel` (message passing).
- **Frontend Architecture**: Tailwind CSS 3.x, HTMX, AlpineJS (Animations/Transitions), Chart.js.

---

## 📝 License

Distributed under the **Apache License, Version 2.0**. See `LICENSE` for more information.
