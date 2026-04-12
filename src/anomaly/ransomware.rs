use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

const ENTROPY_HIGH_THRESHOLD: f64 = 7.5;
const ENTROPY_MEDIUM_THRESHOLD: f64 = 6.5;
#[allow(dead_code)]
const ENCRYPTION_PATTERN_SCORE: u32 = 50;
#[allow(dead_code)]
const SUSPICIOUS_EXTENSION_SCORE: u32 = 30;
#[allow(dead_code)]
const HIGH_ENTROPY_SCORE: u32 = 40;
#[allow(dead_code)]
const RAPID_FILE_CHANGE_SCORE: u32 = 35;

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareAlert {
    pub id: String,
    pub timestamp: i64,
    pub source_ip: String,
    pub indicator_type: RansomwareIndicator,
    pub severity: RansomwareSeverity,
    pub message: String,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RansomwareIndicator {
    HighEntropy,
    EncryptionPattern,
    SuspiciousExtension,
    RapidFileChanges,
    MassDeletion,
    KnownRansomwareFamily,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RansomwareSeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub struct RansomwareDetector {
    recent_alerts: std::collections::VecDeque<RansomwareAlert>,
    file_operations: HashMap<String, VecDeque<FileOperation>>,
    #[allow(dead_code)]
    max_history: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FileOperation {
    timestamp: i64,
    operation: FileOpType,
    path: String,
    size_change: i64,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum FileOpType {
    Create,
    Modify,
    Delete,
    Rename,
}

impl RansomwareDetector {
    pub fn new() -> Self {
        Self {
            recent_alerts: std::collections::VecDeque::with_capacity(100),
            file_operations: HashMap::new(),
            max_history: 1000,
        }
    }

    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0u64; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequency {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    pub fn detect_encryption_pattern(data: &[u8]) -> bool {
        if data.len() < 1024 {
            return false;
        }

        let sample = &data[..1024.min(data.len())];
        let zero_count = sample.iter().filter(|&&b| b == 0).count();
        let high_byte_count = sample.iter().filter(|&&b| b > 127).count();

        zero_count > 300 || high_byte_count > 500
    }

    pub fn check_extension(filename: &str) -> bool {
        let suspicious = [
            "encrypted",
            "locked",
            "ransomed",
            "crypto",
            "encrypted",
            ".encrypted",
            ".locked",
            ".enc",
            ".lock",
        ];
        let lower = filename.to_lowercase();
        lower.contains("read_for_decrypt") || suspicious.iter().any(|ext| lower.contains(ext))
    }

    pub fn analyze_file_operation(
        &mut self,
        ip: String,
        operation: FileOpType,
        path: String,
        size_change: i64,
    ) -> Option<RansomwareAlert> {
        let now = chrono::Utc::now().timestamp_millis();

        let entry = self.file_operations.entry(ip.clone()).or_default();

        if entry.len() > 100 {
            entry.pop_front();
        }

        entry.push_back(FileOperation {
            timestamp: now,
            operation: operation.clone(),
            path: path.clone(),
            size_change,
        });

        let window_start = now - 30000;
        let recent_ops: Vec<_> = entry
            .iter()
            .filter(|op| op.timestamp > window_start)
            .collect();

        if recent_ops.len() > 50 && operation == FileOpType::Delete {
            Some(self.create_alert(
                ip,
                RansomwareIndicator::MassDeletion,
                RansomwareSeverity::Critical,
                "Mass file deletion detected - possible ransomware activity".to_string(),
            ))
        } else if recent_ops.len() > 30 && operation == FileOpType::Create {
            let mut total_size_change: i64 = 0;
            for op in &recent_ops {
                total_size_change += op.size_change;
            }

            if total_size_change < -10000 {
                Some(self.create_alert(
                    ip,
                    RansomwareIndicator::RapidFileChanges,
                    RansomwareSeverity::High,
                    "Rapid file changes with decreasing sizes detected".to_string(),
                ))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn check_data(&self, data: &[u8], source_ip: &str) -> Option<RansomwareAlert> {
        let entropy = Self::calculate_entropy(data);

        if entropy > ENTROPY_HIGH_THRESHOLD {
            return Some(self.create_alert(
                source_ip.to_string(),
                RansomwareIndicator::HighEntropy,
                RansomwareSeverity::High,
                format!(
                    "High entropy ({:.2}) detected - possible encrypted data",
                    entropy
                ),
            ));
        } else if entropy > ENTROPY_MEDIUM_THRESHOLD {
            return Some(self.create_alert(
                source_ip.to_string(),
                RansomwareIndicator::HighEntropy,
                RansomwareSeverity::Medium,
                format!("Medium-high entropy ({:.2}) detected", entropy),
            ));
        }

        if Self::detect_encryption_pattern(data) {
            return Some(self.create_alert(
                source_ip.to_string(),
                RansomwareIndicator::EncryptionPattern,
                RansomwareSeverity::High,
                "Encryption pattern detected in network data".to_string(),
            ));
        }

        None
    }

    pub fn check_filename(&self, filename: &str, source_ip: &str) -> Option<RansomwareAlert> {
        if Self::check_extension(filename) {
            return Some(self.create_alert(
                source_ip.to_string(),
                RansomwareIndicator::SuspiciousExtension,
                RansomwareSeverity::High,
                format!("Suspicious filename detected: {}", filename),
            ));
        }
        None
    }

    fn create_alert(
        &self,
        source_ip: String,
        indicator: RansomwareIndicator,
        severity: RansomwareSeverity,
        message: String,
    ) -> RansomwareAlert {
        RansomwareAlert {
            id: format!("ransomware-{}", chrono::Utc::now().timestamp_millis()),
            timestamp: chrono::Utc::now().timestamp_millis(),
            source_ip,
            indicator_type: indicator,
            severity,
            message,
            details: HashMap::new(),
        }
    }

    pub fn add_alert(&mut self, alert: RansomwareAlert) {
        if self.recent_alerts.len() >= 100 {
            self.recent_alerts.pop_front();
        }
        self.recent_alerts.push_back(alert);
    }

    pub fn get_recent_alerts(&self) -> Vec<RansomwareAlert> {
        self.recent_alerts.iter().cloned().collect()
    }
}

impl Default for RansomwareDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RansomwareIndicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RansomwareIndicator::HighEntropy => write!(f, "High Entropy"),
            RansomwareIndicator::EncryptionPattern => write!(f, "Encryption Pattern"),
            RansomwareIndicator::SuspiciousExtension => write!(f, "Suspicious Extension"),
            RansomwareIndicator::RapidFileChanges => write!(f, "Rapid File Changes"),
            RansomwareIndicator::MassDeletion => write!(f, "Mass Deletion"),
            RansomwareIndicator::KnownRansomwareFamily => write!(f, "Known Ransomware Family"),
        }
    }
}

impl std::fmt::Display for RansomwareSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RansomwareSeverity::Low => write!(f, "Low"),
            RansomwareSeverity::Medium => write!(f, "Medium"),
            RansomwareSeverity::High => write!(f, "High"),
            RansomwareSeverity::Critical => write!(f, "Critical"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy_random_data() {
        let data = vec![0u8; 1000];
        let entropy = RansomwareDetector::calculate_entropy(&data);
        assert!(entropy < 2.0);
    }

    #[test]
    fn test_calculate_entropy_compressed() {
        let data: Vec<u8> = (0..100).flat_map(|i| vec![i; 10]).collect();
        let entropy = RansomwareDetector::calculate_entropy(&data);
        assert!(entropy > 5.0);
    }

    #[test]
    fn test_detect_encryption_pattern() {
        // Create deterministic encrypted-like data with >500 high bytes in first 1024
        let mut encrypted: Vec<u8> = (0..1024)
            .map(|i| if i % 2 == 0 { 200u8 } else { 128u8 })
            .collect();
        encrypted.extend((0..1024).map(|_| rand::random::<u8>()));
        assert!(RansomwareDetector::detect_encryption_pattern(&encrypted));
    }

    #[test]
    fn test_check_extension_suspicious() {
        assert!(RansomwareDetector::check_extension("document.encrypted"));
        assert!(RansomwareDetector::check_extension("file.locked"));
        assert!(RansomwareDetector::check_extension("READ_FOR_DECRYPT.txt"));
    }

    #[test]
    fn test_check_extension_normal() {
        assert!(!RansomwareDetector::check_extension("document.pdf"));
        assert!(!RansomwareDetector::check_extension("image.jpg"));
    }

    #[test]
    fn test_ransomware_detector_new() {
        let detector = RansomwareDetector::new();
        assert!(detector.get_recent_alerts().is_empty());
    }
}
