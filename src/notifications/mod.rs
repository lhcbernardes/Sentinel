use serde::{Deserialize, Serialize};

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
            client: reqwest::Client::new(),
        }
    }

    pub fn configure_telegram(&self, config: TelegramConfig) {
        self.config.write().telegram = Some(config);
    }

    pub fn configure_slack(&self, config: SlackConfig) {
        self.config.write().slack = Some(config);
    }

    pub fn configure_email(&self, config: EmailConfig) {
        self.config.write().email = Some(config);
    }

    pub async fn send(&self, notification: NotificationMessage) {
        let config = self.config.read().clone();

        if let Some(telegram) = &config.telegram {
            if telegram.enabled {
                self.send_telegram(telegram, &notification).await;
            }
        }

        if let Some(slack) = &config.slack {
            if slack.enabled {
                self.send_slack(slack, &notification).await;
            }
        }

        if let Some(email) = &config.email {
            if email.enabled {
                self.send_email(email, &notification).await;
            }
        }
    }

    async fn send_telegram(&self, config: &TelegramConfig, notification: &NotificationMessage) {
        let emoji = match notification.severity {
            NotificationSeverity::Info => "ℹ️",
            NotificationSeverity::Warning => "⚠️",
            NotificationSeverity::Error => "❌",
            NotificationSeverity::Critical => "🔴",
        };

        let text = format!(
            "{} *{}*\n\n{}\n\n⏰ {}",
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

            if let Err(e) = self.client.post(&url).json(&body).send().await {
                tracing::warn!("Failed to send Telegram notification: {}", e);
            }
        }
    }

    async fn send_slack(&self, config: &SlackConfig, notification: &NotificationMessage) {
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

        if let Err(e) = self
            .client
            .post(&config.webhook_url)
            .json(&payload)
            .send()
            .await
        {
            tracing::warn!("Failed to send Slack notification: {}", e);
        }
    }

    async fn send_email(&self, config: &EmailConfig, notification: &NotificationMessage) {
        // Email sending requires more complex SMTP handling
        // For now, we'll log the attempt
        tracing::info!(
            "Email notification: {} - {} to {:?}",
            notification.title,
            notification.message,
            config.to_emails
        );
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
