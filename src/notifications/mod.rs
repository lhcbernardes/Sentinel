use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub telegram: Option<TelegramConfig>,
    pub slack: Option<SlackConfig>,
    pub email: Option<EmailConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub enabled: bool,
    pub webhook_url: String,
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub to_emails: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationMessage {
    pub title: String,
    pub message: String,
    pub severity: NotificationSeverity,
    pub timestamp: i64,
    pub source: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NotificationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Per-channel send timeout.
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct NotificationManager {
    config: parking_lot::RwLock<NotificationConfig>,
    client: reqwest::Client,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self {
            config: parking_lot::RwLock::new(NotificationConfig {
                telegram: None,
                slack: None,
                email: None,
            }),
            client: reqwest::Client::builder()
                .timeout(CHANNEL_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub fn configure_telegram(&self, config: TelegramConfig) -> Result<(), String> {
        if config.bot_token.is_empty() {
            return Err("Telegram bot_token cannot be empty".to_string());
        }
        if config.chat_ids.is_empty() {
            return Err("Telegram chat_ids cannot be empty".to_string());
        }
        self.config.write().telegram = Some(config);
        Ok(())
    }

    pub fn configure_slack(&self, config: SlackConfig) -> Result<(), String> {
        if config.webhook_url.is_empty() {
            return Err("Slack webhook_url cannot be empty".to_string());
        }
        // Validate URL format
        if url::Url::parse(&config.webhook_url).is_err() {
            return Err("Slack webhook_url is not a valid URL".to_string());
        }
        self.config.write().slack = Some(config);
        Ok(())
    }

    pub fn configure_email(&self, config: EmailConfig) -> Result<(), String> {
        if config.smtp_server.is_empty() {
            return Err("SMTP server cannot be empty".to_string());
        }
        if config.smtp_port == 0 {
            return Err("SMTP port must be > 0".to_string());
        }
        if config.to_emails.is_empty() {
            return Err("Email recipients cannot be empty".to_string());
        }
        self.config.write().email = Some(config);
        Ok(())
    }

    /// Send notification to all configured and enabled channels in parallel.
    /// Returns a list of errors for channels that failed.
    pub async fn send(&self, notification: NotificationMessage) -> Vec<String> {
        let config = self.config.read().clone();
        let mut errors = Vec::new();

        // Send to all channels concurrently with individual timeouts
        let (tg_result, sl_result, em_result) = tokio::join!(
            self.send_telegram_safe(&config.telegram, &notification),
            self.send_slack_safe(&config.slack, &notification),
            self.send_email_safe(&config.email, &notification),
        );

        if let Err(e) = tg_result {
            errors.push(format!("Telegram: {}", e));
        }
        if let Err(e) = sl_result {
            errors.push(format!("Slack: {}", e));
        }
        if let Err(e) = em_result {
            errors.push(format!("Email: {}", e));
        }

        if !errors.is_empty() {
            tracing::warn!("Notification errors: {:?}", errors);
        }

        errors
    }

    async fn send_telegram_safe(
        &self,
        config: &Option<TelegramConfig>,
        notification: &NotificationMessage,
    ) -> Result<(), String> {
        let config = match config {
            Some(c) if c.enabled => c,
            _ => return Ok(()),
        };

        let emoji = match notification.severity {
            NotificationSeverity::Info => "i",
            NotificationSeverity::Warning => "!",
            NotificationSeverity::Error => "X",
            NotificationSeverity::Critical => "!!",
        };

        let text = format!(
            "[{}] *{}*\n\n{}\n\n{}",
            emoji,
            notification.title,
            notification.message,
            chrono::DateTime::from_timestamp(notification.timestamp, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default()
        );

        for chat_id in &config.chat_ids {
            let url = format!(
                "https://api.telegram.org/bot{}/sendMessage",
                config.bot_token
            );

            let body = serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown"
            });

            self.client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Failed to send to chat {}: {}", chat_id, e))?;
        }

        Ok(())
    }

    async fn send_slack_safe(
        &self,
        config: &Option<SlackConfig>,
        notification: &NotificationMessage,
    ) -> Result<(), String> {
        let config = match config {
            Some(c) if c.enabled => c,
            _ => return Ok(()),
        };

        let color = match notification.severity {
            NotificationSeverity::Info => "#36a64f",
            NotificationSeverity::Warning => "#ff9800",
            NotificationSeverity::Error => "#f44336",
            NotificationSeverity::Critical => "#b71c1c",
        };

        let payload = serde_json::json!({
            "attachments": [{
                "color": color,
                "title": notification.title,
                "text": notification.message,
                "footer": notification.source,
                "ts": notification.timestamp
            }]
        });

        self.client
            .post(&config.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Slack webhook error: {}", e))?;

        Ok(())
    }

    async fn send_email_safe(
        &self,
        config: &Option<EmailConfig>,
        notification: &NotificationMessage,
    ) -> Result<(), String> {
        let config = match config {
            Some(c) if c.enabled => c,
            _ => return Ok(()),
        };

        // Email sending requires SMTP library (not yet implemented).
        // Log for now so callers know it was attempted.
        tracing::info!(
            "Email notification (SMTP not implemented): {} - {} to {:?}",
            notification.title,
            notification.message,
            config.to_emails
        );

        Ok(())
    }

    pub fn get_config(&self) -> NotificationConfig {
        self.config.read().clone()
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
}
