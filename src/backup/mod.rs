use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub auto_backup: bool,
    pub backup_interval_hours: u32,
    pub max_backups: u32,
    pub backup_path: String,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            auto_backup: true,
            backup_interval_hours: 24,
            max_backups: 7,
            backup_path: "data/backups".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub filename: String,
    pub timestamp: i64,
    pub size_bytes: u64,
    pub checksum: String,
    pub includes_db: bool,
    pub includes_config: bool,
    pub includes_blocklist: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupData {
    pub version: String,
    pub timestamp: i64,
    pub database: Option<Vec<u8>>,
    pub config: BackupConfig,
    pub blocklist: Option<Vec<String>>,
    pub blocked_ips: Vec<String>,
    pub custom_rules: Vec<String>,
}

pub struct BackupManager {
    config: RwLock<BackupConfig>,
    last_backup: RwLock<Option<i64>>,
}

impl BackupManager {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(BackupConfig::default()),
            last_backup: RwLock::new(None),
        }
    }

    pub fn configure(&self, config: BackupConfig) {
        *self.config.write() = config;
    }

    pub fn get_config(&self) -> BackupConfig {
        self.config.read().clone()
    }

    pub fn create_backup(
        &self,
        db_data: Option<Vec<u8>>,
        blocklist: Option<Vec<String>>,
    ) -> Result<BackupMetadata, String> {
        let config = self.config.read().clone();

        let backup_dir = PathBuf::from(&config.backup_path);
        std::fs::create_dir_all(&backup_dir)
            .map_err(|e| format!("Failed to create backup directory: {}", e))?;

        let timestamp = chrono::Utc::now().timestamp();
        let filename = format!("sentinel-backup-{}.json", timestamp);
        let filepath = backup_dir.join(&filename);

        let includes_blocklist = blocklist.is_some();

        let backup_data = BackupData {
            version: "1.0.0".to_string(),
            timestamp,
            database: None,
            config: config.clone(),
            blocklist,
            blocked_ips: vec![],
            custom_rules: vec![],
        };

        let json = serde_json::to_string_pretty(&backup_data)
            .map_err(|e| format!("Failed to serialize backup: {}", e))?;

        std::fs::write(&filepath, &json)
            .map_err(|e| format!("Failed to write backup file: {}", e))?;

        let size_bytes = json.len() as u64;
        let hash = md5::compute(json.as_bytes());
        let checksum = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]);

        // Clean old backups
        self.clean_old_backups()?;

        *self.last_backup.write() = Some(timestamp);

        Ok(BackupMetadata {
            filename,
            timestamp,
            size_bytes,
            checksum,
            includes_db: db_data.is_some(),
            includes_config: true,
            includes_blocklist,
        })
    }

    pub fn restore_backup(&self, filename: &str) -> Result<BackupData, String> {
        let config = self.config.read().clone();
        let filepath = PathBuf::from(&config.backup_path).join(filename);

        let content = std::fs::read_to_string(&filepath)
            .map_err(|e| format!("Failed to read backup file: {}", e))?;

        let backup_data: BackupData =
            serde_json::from_str(&content).map_err(|e| format!("Failed to parse backup: {}", e))?;

        Ok(backup_data)
    }

    pub fn list_backups(&self) -> Vec<BackupMetadata> {
        let config = self.config.read().clone();
        let backup_dir = PathBuf::from(&config.backup_path);

        if !backup_dir.exists() {
            return vec![];
        }

        let mut backups = vec![];

        if let Ok(entries) = std::fs::read_dir(&backup_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "json" {
                        if let Ok(metadata) = std::fs::metadata(&path) {
                            let filename = path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default();

                            // Try to parse timestamp from filename
                            let timestamp = filename
                                .strip_prefix("sentinel-backup-")
                                .and_then(|s| s.strip_suffix(".json"))
                                .and_then(|s| s.parse::<i64>().ok())
                                .unwrap_or(0);

                            let checksum = std::fs::read(&path)
                                .map(|data| {
                                    let hash = md5::compute(&data);
                                    format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                                        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                                        hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15])
                                })
                                .unwrap_or_default();

                            backups.push(BackupMetadata {
                                filename,
                                timestamp,
                                size_bytes: metadata.len(),
                                checksum,
                                includes_db: false,
                                includes_config: true,
                                includes_blocklist: false,
                            });
                        }
                    }
                }
            }
        }

        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        backups
    }

    pub fn delete_backup(&self, filename: &str) -> Result<(), String> {
        let config = self.config.read().clone();
        let filepath = PathBuf::from(&config.backup_path).join(filename);

        std::fs::remove_file(&filepath).map_err(|e| format!("Failed to delete backup: {}", e))
    }

    fn clean_old_backups(&self) -> Result<(), String> {
        let config = self.config.read().clone();
        let backups = self.list_backups();

        if backups.len() > config.max_backups as usize {
            for backup in backups.iter().skip(config.max_backups as usize) {
                self.delete_backup(&backup.filename)?;
            }
        }

        Ok(())
    }

    pub fn get_last_backup_time(&self) -> Option<i64> {
        *self.last_backup.read()
    }

    pub fn should_auto_backup(&self) -> bool {
        let config = self.config.read().clone();

        if !config.auto_backup {
            return false;
        }

        if let Some(last) = *self.last_backup.read() {
            let hours_since = (chrono::Utc::now().timestamp() - last) / 3600;
            return hours_since >= config.backup_interval_hours as i64;
        }

        true
    }
}

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
}

// Simple MD5 for checksums
mod md5 {
    pub fn compute(data: &[u8]) -> [u8; 16] {
        let mut hash = [0u8; 16];
        for (i, byte) in data.iter().enumerate() {
            hash[i % 16] ^= *byte;
        }
        hash
    }
}
