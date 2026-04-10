use parking_lot::Mutex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tracing::info;

use crate::anomaly::detector::{Alert, AlertType, Severity};
use crate::devices::Device;

pub struct Database {
    conn: Arc<Mutex<Connection>>,
    path: std::path::PathBuf,
}

impl Database {
    pub fn new(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("Failed to open database: {}", e))?;

        // Performance pragmas: WAL mode for concurrent reads+writes,
        // NORMAL sync for better write throughput with reasonable safety,
        // busy_timeout to retry on lock contention instead of failing immediately.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA cache_size = -8000;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| format!("Failed to set database pragmas: {}", e))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            path: path.to_path_buf(),
        };

        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), String> {
        let conn = self.conn.lock();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                manufacturer TEXT,
                first_seen INTEGER,
                last_seen INTEGER,
                packet_count INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                open_ports TEXT,
                risk_level TEXT,
                is_local INTEGER
            )",
            [],
        )
        .map_err(|e| format!("Failed to create devices table: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp INTEGER,
                alert_type TEXT,
                source_ip TEXT,
                target_ip TEXT,
                message TEXT,
                severity TEXT
            )",
            [],
        )
        .map_err(|e| format!("Failed to create alerts table: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                size INTEGER,
                src_mac TEXT,
                dst_mac TEXT
            )",
            [],
        )
        .map_err(|e| format!("Failed to create packets table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)",
            [],
        )
        .map_err(|e| format!("Failed to create index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
            [],
        )
        .map_err(|e| format!("Failed to create alerts timestamp index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)",
            [],
        )
        .map_err(|e| format!("Failed to create devices last_seen index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)",
            [],
        )
        .map_err(|e| format!("Failed to create packets src_ip index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)",
            [],
        )
        .map_err(|e| format!("Failed to create packets dst_ip index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol)",
            [],
        )
        .map_err(|e| format!("Failed to create packets protocol index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)",
            [],
        )
        .map_err(|e| format!("Failed to create alerts source_ip index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)",
            [],
        )
        .map_err(|e| format!("Failed to create devices ip_address index: {}", e))?;

        info!("Database schema initialized");
        Ok(())
    }

    pub fn save_device(&self, device: &Device) -> Result<(), String> {
        let conn = self.conn.lock();
        let open_ports =
            serde_json::to_string(&device.open_ports).unwrap_or_else(|_| "[]".to_string());

        conn.execute(
            "INSERT INTO devices 
             (mac_address, ip_address, hostname, manufacturer, first_seen, last_seen, 
              packet_count, total_bytes, open_ports, risk_level, is_local)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(mac_address) DO UPDATE SET
              ip_address=excluded.ip_address,
              hostname=excluded.hostname,
              manufacturer=excluded.manufacturer,
              last_seen=excluded.last_seen,
              packet_count=excluded.packet_count,
              total_bytes=excluded.total_bytes,
              open_ports=excluded.open_ports,
              risk_level=excluded.risk_level,
              is_local=excluded.is_local",
            params![
                device.mac_address,
                device.ip_address,
                device.hostname,
                device.manufacturer,
                device.first_seen,
                device.last_seen,
                device.packet_count,
                device.total_bytes,
                open_ports,
                device.risk_level.to_string(),
                device.is_local as i32,
            ],
        )
        .map_err(|e| format!("Failed to save device: {}", e))?;

        Ok(())
    }

    pub fn save_alert(&self, alert: &Alert) -> Result<(), String> {
        let conn = self.conn.lock();

        conn.execute(
            "INSERT INTO alerts 
             (id, timestamp, alert_type, source_ip, target_ip, message, severity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
              timestamp=excluded.timestamp,
              alert_type=excluded.alert_type,
              source_ip=excluded.source_ip,
              target_ip=excluded.target_ip,
              message=excluded.message,
              severity=excluded.severity",
            params![
                alert.id,
                alert.timestamp,
                format!("{:?}", alert.alert_type),
                alert.source_ip,
                alert.target_ip,
                alert.message,
                format!("{:?}", alert.severity),
            ],
        )
        .map_err(|e| format!("Failed to save alert: {}", e))?;

        Ok(())
    }

    /// Batch insert packets using multi-row INSERT for better performance.
    pub fn save_packets_batch(&self, packets: &[crate::sniffer::PacketInfo]) {
        if packets.is_empty() {
            return;
        }

        let mut values = Vec::with_capacity(packets.len());
        for packet in packets {
            let src_ip = packet.src_ip.to_string();
            let dst_ip = packet.dst_ip.to_string();
            let protocol = packet.protocol.to_string();
            let src_port = packet.src_port.unwrap_or(0);
            let dst_port = packet.dst_port.unwrap_or(0);
            let src_mac = packet.src_mac.as_deref().unwrap_or("");
            let dst_mac = packet.dst_mac.as_deref().unwrap_or("");

            values.push(format!(
                "({}, '{}', '{}', {}, {}, '{}', {}, '{}', '{}')",
                packet.timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                packet.size,
                src_mac,
                dst_mac
            ));
        }

        let query = format!(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, src_mac, dst_mac) VALUES {}",
            values.join(",")
        );

        let conn = self.conn.lock();
        if let Err(e) = conn.execute_batch(&query) {
            tracing::warn!("Failed to batch insert packets: {}", e);
        }
    }

    pub fn save_packet(&self, packet: &crate::sniffer::PacketInfo) -> Result<(), String> {
        let conn = self.conn.lock();

        conn.execute(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, src_mac, dst_mac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                packet.timestamp,
                packet.src_ip.to_string(),
                packet.dst_ip.to_string(),
                packet.src_port,
                packet.dst_port,
                packet.protocol.to_string(),
                packet.size,
                packet.src_mac,
                packet.dst_mac,
            ],
        ).map_err(|e| format!("Failed to save packet: {}", e))?;

        Ok(())
    }

    pub fn get_devices(&self) -> Result<Vec<Device>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT mac_address, ip_address, hostname, manufacturer, first_seen, last_seen,
                    packet_count, total_bytes, open_ports, risk_level, is_local
             FROM devices ORDER BY last_seen DESC",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let devices = stmt
            .query_map([], |row| {
                let open_ports: String = row.get(8)?;
                let open_ports: Vec<u16> = serde_json::from_str(&open_ports).unwrap_or_default();
                let risk_level: String = row.get(9)?;

                Ok(Device {
                    mac_address: row.get(0)?,
                    ip_address: row.get(1)?,
                    hostname: row.get(2)?,
                    manufacturer: row.get(3)?,
                    first_seen: row.get(4)?,
                    last_seen: row.get(5)?,
                    packet_count: row.get(6)?,
                    total_bytes: row.get(7)?,
                    open_ports,
                    risk_level: match risk_level.as_str() {
                        "Low" => crate::devices::RiskLevel::Low,
                        "Medium" => crate::devices::RiskLevel::Medium,
                        "High" => crate::devices::RiskLevel::High,
                        "Critical" => crate::devices::RiskLevel::Critical,
                        _ => crate::devices::RiskLevel::Low,
                    },
                    is_local: row.get::<_, i32>(10)? != 0,
                })
            })
            .map_err(|e| format!("Failed to query: {}", e))?;

        devices
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to collect devices: {}", e))
    }

    pub fn get_alerts(&self, limit: usize) -> Result<Vec<Alert>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, timestamp, alert_type, source_ip, target_ip, message, severity
             FROM alerts ORDER BY timestamp DESC LIMIT ?1",
            )
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let alerts = stmt
            .query_map([limit as i64], |row| {
                let alert_type: String = row.get(2)?;
                let severity: String = row.get(6)?;

                Ok(Alert {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    alert_type: match alert_type.as_str() {
                        "NewDevice" => AlertType::NewDevice,
                        "PortScan" => AlertType::PortScan,
                        _ => AlertType::SuspiciousTraffic,
                    },
                    source_ip: row.get(3)?,
                    target_ip: row.get(4)?,
                    message: row.get(5)?,
                    severity: match severity.as_str() {
                        "Info" => Severity::Info,
                        "Warning" => Severity::Warning,
                        "Critical" => Severity::Critical,
                        _ => Severity::Info,
                    },
                })
            })
            .map_err(|e| format!("Failed to query: {}", e))?;

        alerts
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to collect alerts: {}", e))
    }

    pub fn cleanup_old_logs(&self, max_age_days: i64) -> Result<usize, String> {
        let conn = self.conn.lock();

        // Use millisecond cutoff since packet timestamps are in millis
        let cutoff_secs = chrono::Utc::now().timestamp() - (max_age_days * 86400);
        let cutoff_millis = cutoff_secs * 1000;

        // Wrap both deletes in a transaction for atomicity
        conn.execute_batch("BEGIN")
            .map_err(|e| format!("Failed to begin cleanup transaction: {}", e))?;

        let packets_deleted = conn
            .execute("DELETE FROM packets WHERE timestamp < ?", [cutoff_millis])
            .map_err(|e| {
                let _ = conn.execute_batch("ROLLBACK");
                format!("Failed to cleanup packets: {}", e)
            })?;

        let alerts_deleted = conn
            .execute("DELETE FROM alerts WHERE timestamp < ?", [cutoff_secs])
            .map_err(|e| {
                let _ = conn.execute_batch("ROLLBACK");
                format!("Failed to cleanup alerts: {}", e)
            })?;

        conn.execute_batch("COMMIT")
            .map_err(|e| format!("Failed to commit cleanup transaction: {}", e))?;

        tracing::info!(
            "Cleaned up {} packets and {} alerts older than {} days",
            packets_deleted,
            alerts_deleted,
            max_age_days
        );

        Ok(packets_deleted + alerts_deleted)
    }

    pub fn get_stats(&self) -> DbStats {
        let conn = self.conn.lock();

        let device_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))
            .unwrap_or(0);

        let alert_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM alerts", [], |row| row.get(0))
            .unwrap_or(0);

        let packet_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM packets", [], |row| row.get(0))
            .unwrap_or(0);

        let db_size_bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);

        DbStats {
            device_count: device_count as usize,
            alert_count: alert_count as usize,
            packet_count: packet_count as usize,
            db_size_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub device_count: usize,
    pub alert_count: usize,
    pub packet_count: usize,
    pub db_size_bytes: u64,
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
            path: self.path.clone(),
        }
    }
}
