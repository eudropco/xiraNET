pub mod channels;
pub mod url_guard;
pub mod webhooks;

use std::sync::{Arc, RwLock};

/// Webhook log/error mesajlarında upstream cevabını sınırlamak için.
/// CR/LF ve ANSI escape'leri elden geçer; uzunluğu kapatır.
fn sanitize_for_log(input: &str, max: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max));
    for c in input.chars().take(max) {
        match c {
            '\r' | '\n' | '\t' => out.push(' '),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    if input.len() > max {
        out.push_str("…[truncated]");
    }
    out
}

#[derive(Clone)]
struct AlertSettings {
    webhook_url: Option<String>,
    enabled: bool,
    on_service_down: bool,
    on_service_up: bool,
}

/// Webhook-based alerting system
#[derive(Clone)]
pub struct AlertManager {
    settings: Arc<RwLock<AlertSettings>>,
    client: Arc<reqwest::Client>,
}

impl AlertManager {
    pub fn new(
        webhook_url: Option<String>,
        enabled: bool,
        on_service_down: bool,
        on_service_up: bool,
    ) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // SSRF: redirect ile filter'i bypass etmeyi engelle
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            settings: Arc::new(RwLock::new(AlertSettings {
                webhook_url,
                enabled,
                on_service_down,
                on_service_up,
            })),
            client: Arc::new(client),
        }
    }

    pub fn update_config(
        &self,
        webhook_url: Option<String>,
        enabled: bool,
        on_service_down: bool,
        on_service_up: bool,
    ) {
        // RwLock poison'ı görmezden gel — config update sırasında panik olduysa
        // okuma tarafı zaten bozuk veri görüyor; içeriği yine de yaz.
        let mut settings = match self.settings.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        settings.webhook_url = webhook_url;
        settings.enabled = enabled;
        settings.on_service_down = on_service_down;
        settings.on_service_up = on_service_up;
    }

    pub fn snapshot(&self) -> (Option<String>, bool, bool, bool) {
        let settings = match self.settings.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        (
            settings.webhook_url.clone(),
            settings.enabled,
            settings.on_service_down,
            settings.on_service_up,
        )
    }

    /// Servis DOWN olduğunda alert gönder
    pub async fn alert_service_down(&self, service_name: &str, service_id: &str, detail: &str) {
        let (webhook_url, enabled, on_service_down, _) = self.snapshot();
        if !enabled || !on_service_down {
            return;
        }

        let payload = serde_json::json!({
            "event": "service_down",
            "severity": "critical",
            "service_name": service_name,
            "service_id": service_id,
            "detail": detail,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "XIRA",
        });

        self.send_webhook(webhook_url, payload).await;
    }

    /// Servis UP olduğunda alert gönder
    pub async fn alert_service_up(&self, service_name: &str, service_id: &str) {
        let (webhook_url, enabled, _, on_service_up) = self.snapshot();
        if !enabled || !on_service_up {
            return;
        }

        let payload = serde_json::json!({
            "event": "service_up",
            "severity": "info",
            "service_name": service_name,
            "service_id": service_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "XIRA",
        });

        self.send_webhook(webhook_url, payload).await;
    }

    /// Generic alert gönder
    pub async fn send_alert(&self, event: &str, severity: &str, message: &str) {
        let (webhook_url, enabled, _, _) = self.snapshot();
        if !enabled {
            return;
        }

        let payload = serde_json::json!({
            "event": event,
            "severity": severity,
            "message": message,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "source": "XIRA",
        });

        self.send_webhook(webhook_url, payload).await;
    }

    async fn send_webhook(&self, webhook_url: Option<String>, payload: serde_json::Value) {
        let url = match webhook_url {
            Some(url) if !url.is_empty() => url,
            _ => {
                tracing::debug!("Alert triggered but no webhook URL configured");
                return;
            }
        };

        // SSRF koruması — internal/loopback/cloud-metadata adreslerini reddet
        if let Err(e) = url_guard::validate_outbound_url(&url).await {
            tracing::warn!(error = %e, "Alert webhook URL rejected by SSRF guard");
            return;
        }

        match self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    tracing::info!(
                        "Alert sent: {}",
                        payload
                            .get("event")
                            .and_then(|e| e.as_str())
                            .unwrap_or("unknown")
                    );
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    tracing::warn!(
                        "Alert webhook returned status {}: {}",
                        status,
                        sanitize_for_log(&body, 256)
                    );
                }
            }
            Err(e) => {
                tracing::error!("Failed to send alert webhook: {}", e);
            }
        }
    }
}
