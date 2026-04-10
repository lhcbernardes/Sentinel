# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Deep Packet Inspection (DPI) module
- NetFlow/IPFIX collector
- SIEM export (syslog, CEF, JSON)
- Prometheus metrics endpoint (`/metrics`)
- Alertmanager integration
- Docker Compose with Prometheus, Grafana, Alertmanager
- Ransomware detection (entropy analysis, behavioral monitoring)
- Grafana dashboards and datasources provisioning

### Changed
- Migrated to Askama 0.12 (breaking API changes)
- Updated to Axum 0.8
- Improved i18n support (EN/PT/ES)
- Refactored blocking system with cross-platform support

### Fixed
- Protocol Distribution chart dimension issue
- Various Rust 1.70+ compatibility issues
- Clippy warnings resolved

## [0.1.0] - 2024-XX-XX

### Added
- Real-time packet sniffer (pcap)
- Device discovery and management
- OUI vendor identification
- Port scan detection
- DNS Sinkhole (with blocklists)
- Firewall integration (iptables/pf)
- Web dashboard (HTMX + TailwindCSS)
- REST API v1
- Server-Sent Events for real-time updates
- SQLite persistence
- JWT authentication
- Blocklist management (60+ sources)
- Parental controls
- DHCP monitoring
- VPN detection
- Backup/restore system
- Notification system

[Unreleased]: https://github.com/sentinel-rs/sentinel-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sentinel-rs/sentinel-rs/releases/tag/v0.1.0