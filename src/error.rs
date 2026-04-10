//! Structured error types for Sentinel-RS.
//!
//! Replaces `Result<_, String>` with typed errors that callers can match on.
//! Migration is incremental — existing `String`-based errors continue to work
//! alongside the new type via the `Other` variant.

/// Central error type for the Sentinel-RS application.
#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Firewall error: {0}")]
    Firewall(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

impl From<String> for SentinelError {
    fn from(s: String) -> Self {
        SentinelError::Other(s)
    }
}

impl From<&str> for SentinelError {
    fn from(s: &str) -> Self {
        SentinelError::Other(s.to_string())
    }
}

/// Convenience alias used throughout the codebase.
pub type Result<T> = std::result::Result<T, SentinelError>;
