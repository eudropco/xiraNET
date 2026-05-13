use crate::alerting::url_guard;
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

/// Telegram URL'i log'a yazılırken bot token'ını redact et.
fn redact_telegram_url(url: &str) -> String {
    // https://api.telegram.org/bot<TOKEN>/sendMessage
    if let Some(idx) = url.find("/bot") {
        let prefix = &url[..idx + 4];
        if let Some(end) = url[idx + 4..].find('/') {
            let suffix = &url[idx + 4 + end..];
            return format!("{prefix}<REDACTED>{suffix}");
        }
    }
    "<REDACTED>".to_string()
}

/// reqwest::Error mesajları content/URL leak edebilir; sanitize et.
fn safe_err_msg(e: &reqwest::Error, fallback_url: Option<&str>) -> String {
    let msg = e.to_string();
    if let Some(url) = fallback_url {
        if msg.contains(url) {
            return msg.replace(url, "<URL_REDACTED>");
        }
    }
    msg
}

impl AlertDispatcher {
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    pub fn add_channel(&mut self, channel: AlertChannel) {
        tracing::info!(
            "Alert channel added: {} ({})",
            channel.name,
            match &channel.channel_type {
                ChannelType::Slack => "Slack",
                ChannelType::Discord => "Discord",
                ChannelType::Telegram { .. } => "Telegram",
                ChannelType::PagerDuty { .. } => "PagerDuty",
                ChannelType::GenericWebhook => "Webhook",
            }
        );
        self.channels.push(channel);
    }

    /// Tüm kanallara alert gönder
    pub async fn dispatch(&self, title: &str, message: &str, severity: &str) {
        for channel in &self.channels {
            if !channel.enabled {
                continue;
            }

            let result = match &channel.channel_type {
                ChannelType::Slack => {
                    self.send_slack(&channel.url, title, message, severity)
                        .await
                }
                ChannelType::Discord => {
                    self.send_discord(&channel.url, title, message, severity)
                        .await
                }
                ChannelType::Telegram { chat_id } => {
                    self.send_telegram(&channel.url, chat_id, title, message)
                        .await
                }
                ChannelType::PagerDuty { routing_key } => {
                    self.send_pagerduty(&channel.url, routing_key, title, message, severity)
                        .await
                }
                ChannelType::GenericWebhook => {
                    self.send_webhook(&channel.url, title, message, severity)
                        .await
                }
            };

            if let Err(e) = result {
                tracing::error!("Alert dispatch failed ({}): {}", channel.name, e);
            }
        }
    }

    async fn validate_or_warn(&self, url: &str, channel_name: &str) -> Result<(), String> {
        if let Err(e) = url_guard::validate_outbound_url(url).await {
            tracing::warn!(
                channel = %channel_name,
                error = %e,
                "Channel URL rejected by SSRF guard"
            );
            return Err(format!("URL rejected: {e}"));
        }
        Ok(())
    }

    async fn check_response(resp: reqwest::Response, channel_name: &str) -> Result<(), String> {
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            // Body'yi sanitize et (CR/LF/control), uzunluğu kapat
            let safe_body = crate::alerting::sanitize_for_log(&body, 256);
            Err(format!(
                "channel '{channel_name}' returned {status}: {safe_body}"
            ))
        }
    }

    async fn send_slack(
        &self,
        url: &str,
        title: &str,
        msg: &str,
        severity: &str,
    ) -> Result<(), String> {
        self.validate_or_warn(url, "slack").await?;
        let color = match severity {
            "critical" => "#dc2626",
            "warning" => "#f59e0b",
            _ => "#10b981",
        };
        let payload = serde_json::json!({
            "attachments": [{
                "color": color,
                "title": format!("XIRA — {}", title),
                "text": msg,
                "footer": "XIRA Platform",
                "ts": chrono::Utc::now().timestamp()
            }]
        });
        let resp = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| safe_err_msg(&e, None))?;
        Self::check_response(resp, "slack").await
    }

    async fn send_discord(
        &self,
        url: &str,
        title: &str,
        msg: &str,
        severity: &str,
    ) -> Result<(), String> {
        self.validate_or_warn(url, "discord").await?;
        let color = match severity {
            "critical" => 0xdc2626u32,
            "warning" => 0xf59e0b,
            _ => 0x10b981,
        };
        let payload = serde_json::json!({
            "embeds": [{
                "title": format!("⚡ XIRA — {}", title),
                "description": msg,
                "color": color,
                "footer": { "text": "XIRA Platform" },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        });
        let resp = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| safe_err_msg(&e, None))?;
        Self::check_response(resp, "discord").await
    }

    async fn send_telegram(
        &self,
        bot_token: &str,
        chat_id: &str,
        title: &str,
        msg: &str,
    ) -> Result<(), String> {
        let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
        // Telegram api.telegram.org public DNS — guard yine de uygulanır.
        // Hatada token leak olmaması için error string'inden URL'i çıkar.
        if let Err(e) = url_guard::validate_outbound_url(&url).await {
            tracing::warn!(
                channel = "telegram",
                error = %e,
                "Telegram URL rejected by SSRF guard"
            );
            return Err(format!("URL rejected: {e}"));
        }
        let text = format!("*⚡ XIRA — {title}*\n{msg}");
        let payload = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown"
        });
        let resp = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                let raw = e.to_string();
                // Token leak'i engelle: URL içerebilir
                if raw.contains(&url) {
                    raw.replace(&url, &redact_telegram_url(&url))
                } else if raw.contains(bot_token) {
                    raw.replace(bot_token, "<REDACTED>")
                } else {
                    raw
                }
            })?;
        Self::check_response(resp, "telegram").await
    }

    async fn send_pagerduty(
        &self,
        url: &str,
        routing_key: &str,
        title: &str,
        msg: &str,
        severity: &str,
    ) -> Result<(), String> {
        self.validate_or_warn(url, "pagerduty").await?;
        let payload = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": format!("XIRA: {}", title),
                "severity": severity,
                "source": "xiranet-gateway",
                "custom_details": { "message": msg }
            }
        });
        let resp = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                let raw = e.to_string();
                if raw.contains(routing_key) {
                    raw.replace(routing_key, "<REDACTED>")
                } else {
                    raw
                }
            })?;
        Self::check_response(resp, "pagerduty").await
    }

    async fn send_webhook(
        &self,
        url: &str,
        title: &str,
        msg: &str,
        severity: &str,
    ) -> Result<(), String> {
        self.validate_or_warn(url, "webhook").await?;
        let payload = serde_json::json!({
            "source": "xiranet",
            "title": title,
            "message": msg,
            "severity": severity,
            "timestamp": chrono::Utc::now().to_rfc3339()
        });
        let resp = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| safe_err_msg(&e, None))?;
        Self::check_response(resp, "webhook").await
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_telegram_token() {
        let url = "https://api.telegram.org/bot1234567:ABC-TOKEN/sendMessage";
        let red = redact_telegram_url(url);
        assert!(!red.contains("ABC-TOKEN"));
        assert!(red.contains("<REDACTED>"));
        assert!(red.contains("/sendMessage"));
    }
}
