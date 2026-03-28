use reqwest::Client;
use std::time::Duration;

/// Custom alerting channels — Slack, Discord, Telegram, PagerDuty, generic webhook
pub struct AlertChannel {
    pub name: String,
    pub channel_type: ChannelType,
    pub url: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum ChannelType {
    Slack,
    Discord,
    Telegram { chat_id: String },
    PagerDuty { routing_key: String },
    GenericWebhook,
}

pub struct AlertDispatcher {
    channels: Vec<AlertChannel>,
    client: Client,
}

impl Default for AlertDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertDispatcher {
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    pub fn add_channel(&mut self, channel: AlertChannel) {
        tracing::info!("Alert channel added: {} ({})", channel.name, match &channel.channel_type {
            ChannelType::Slack => "Slack",
            ChannelType::Discord => "Discord",
            ChannelType::Telegram { .. } => "Telegram",
            ChannelType::PagerDuty { .. } => "PagerDuty",
            ChannelType::GenericWebhook => "Webhook",
        });
        self.channels.push(channel);
    }

    /// Tüm kanallara alert gönder
    pub async fn dispatch(&self, title: &str, message: &str, severity: &str) {
        for channel in &self.channels {
            if !channel.enabled { continue; }

            let result = match &channel.channel_type {
                ChannelType::Slack => self.send_slack(&channel.url, title, message, severity).await,
                ChannelType::Discord => self.send_discord(&channel.url, title, message, severity).await,
                ChannelType::Telegram { chat_id } => self.send_telegram(&channel.url, chat_id, title, message).await,
                ChannelType::PagerDuty { routing_key } => self.send_pagerduty(&channel.url, routing_key, title, message, severity).await,
                ChannelType::GenericWebhook => self.send_webhook(&channel.url, title, message, severity).await,
            };

            if let Err(e) = result {
                tracing::error!("Alert dispatch failed ({}): {}", channel.name, e);
            }
        }
    }

    async fn send_slack(&self, url: &str, title: &str, msg: &str, severity: &str) -> Result<(), String> {
        let color = match severity { "critical" => "#dc2626", "warning" => "#f59e0b", _ => "#10b981" };
        let payload = serde_json::json!({
            "attachments": [{
                "color": color,
                "title": format!("xiraNET — {}", title),
                "text": msg,
                "footer": "xiraNET Gateway",
                "ts": chrono::Utc::now().timestamp()
            }]
        });
        self.client.post(url).json(&payload).send().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn send_discord(&self, url: &str, title: &str, msg: &str, severity: &str) -> Result<(), String> {
        let color = match severity { "critical" => 0xdc2626u32, "warning" => 0xf59e0b, _ => 0x10b981 };
        let payload = serde_json::json!({
            "embeds": [{
                "title": format!("⚡ xiraNET — {}", title),
                "description": msg,
                "color": color,
                "footer": { "text": "xiraNET Gateway" },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        });
        self.client.post(url).json(&payload).send().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn send_telegram(&self, bot_token: &str, chat_id: &str, title: &str, msg: &str) -> Result<(), String> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
        let text = format!("*⚡ xiraNET — {}*\n{}", title, msg);
        let payload = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown"
        });
        self.client.post(&url).json(&payload).send().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn send_pagerduty(&self, url: &str, routing_key: &str, title: &str, msg: &str, severity: &str) -> Result<(), String> {
        let payload = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": format!("xiraNET: {}", title),
                "severity": severity,
                "source": "xiranet-gateway",
                "custom_details": { "message": msg }
            }
        });
        self.client.post(url).json(&payload).send().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn send_webhook(&self, url: &str, title: &str, msg: &str, severity: &str) -> Result<(), String> {
        let payload = serde_json::json!({
            "source": "xiranet",
            "title": title,
            "message": msg,
            "severity": severity,
            "timestamp": chrono::Utc::now().to_rfc3339()
        });
        self.client.post(url).json(&payload).send().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}
