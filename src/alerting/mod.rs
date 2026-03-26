pub mod channels;
pub mod webhooks;

use std::sync::Arc;

/// Webhook-based alerting system
#[derive(Clone)]
pub struct AlertManager {
    webhook_url: Option<String>,
    enabled: bool,
    on_service_down: bool,
    on_service_up: bool,
    client: Arc<reqwest::Client>,
}

impl AlertManager {
    pub fn new(
        webhook_url: Option<String>,
        enabled: bool,
        on_service_down: bool,
        on_service_up: bool,
    ) -> Self {
        Self {
            webhook_url,
            enabled,
            on_service_down,
            on_service_up,
            client: Arc::new(reqwest::Client::new()),
        }
    }

    /// Servis DOWN olduğunda alert gönder
    pub async fn alert_service_down(&self, service_name: &str, service_id: &str, detail: &str) {
        if !self.enabled || !self.on_service_down {
            return;
        }

        let payload = serde_json::json!({
            "event": "service_down",
            "severity": "critical",
            "service_name": service_name,
            "service_id": service_id,
            "detail": detail,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "xiraNET",
        });

        self.send_webhook(payload).await;
    }

    /// Servis UP olduğunda alert gönder
    pub async fn alert_service_up(&self, service_name: &str, service_id: &str) {
        if !self.enabled || !self.on_service_up {
            return;
        }

        let payload = serde_json::json!({
            "event": "service_up",
            "severity": "info",
            "service_name": service_name,
            "service_id": service_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "xiraNET",
        });

        self.send_webhook(payload).await;
    }

    /// Generic alert gönder
    pub async fn send_alert(&self, event: &str, severity: &str, message: &str) {
        if !self.enabled {
            return;
        }

        let payload = serde_json::json!({
            "event": event,
            "severity": severity,
            "message": message,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "xiraNET",
        });

        self.send_webhook(payload).await;
    }

    async fn send_webhook(&self, payload: serde_json::Value) {
        let url = match &self.webhook_url {
            Some(url) if !url.is_empty() => url.clone(),
            _ => {
                tracing::debug!("Alert triggered but no webhook URL configured");
                return;
            }
        };

        match self.client
            .post(&url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    tracing::info!("Alert sent: {}", payload.get("event").and_then(|e| e.as_str()).unwrap_or("unknown"));
                } else {
                    tracing::warn!(
                        "Alert webhook returned status {}: {}",
                        resp.status(),
                        resp.text().await.unwrap_or_default()
                    );
                }
            }
            Err(e) => {
                tracing::error!("Failed to send alert webhook: {}", e);
            }
        }
    }
}
