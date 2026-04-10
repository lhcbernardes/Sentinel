# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please send an email to:
- security@sentinel-rs.io

Please include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any possible fixes

We aim to respond within 48 hours.

## Security Considerations

### Privilege Requirements
Sentinel-RS requires root privileges for:
- Packet capture (libpcap)
- DNS sinkhole (port 53)
- Firewall rule management (iptables/pf)

### Best Practices
1. **Network Isolation** - Run in isolated network segment
2. **Access Control** - Use strong passwords and change defaults
3. **Regular Updates** - Keep blocklists updated
4. **Monitoring** - Review alerts regularly

### Known Limitations
- No encryption for internal communication (use VPN)
- Limited to IPv4 (IPv6 support planned)
- Single-node deployment (cluster support planned)

## Dependency Security

We use `cargo-audit` to check for vulnerable dependencies:

```bash
cargo audit
```

## Security Updates

Security updates will be released as patch versions and announced via:
- GitHub Security Advisories
- Release notes

## Third-Party Libraries

All dependencies are audited regularly. Key dependencies:
- tokio - Async runtime (MPL 2.0)
- axum - Web framework (MIT)
- rusqlite - Database (MIT)
- pcap - Packet capture (BSD)