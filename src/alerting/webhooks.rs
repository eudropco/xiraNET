/// Webhook Registry — servis event'lerini webhook'lara otomatik bildir
use crate::alerting::url_guard;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub struct WebhookRegistry {
    webhooks: DashMap<String, WebhookConfig>,
    client: Client,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WebhookConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: Vec<String>, // "service.up", "service.down", "sla.violation", "circuit_breaker.open"
    pub enabled: bool,
    pub secret: Option<String>,
    pub delivery_count: u64,
    pub failure_count: u64,
}

impl Default for WebhookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookRegistry {
    pub fn new() -> Self {
        Self {
            webhooks: DashMap::new(),
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    /// Webhook kaydet. URL kaydedilmeden önce SSRF guard'dan geçer.
    pub async fn register(
        &self,
        name: String,
        url: String,
        events: Vec<String>,
        secret: Option<String>,
    ) -> Result<String, String> {
        url_guard::validate_outbound_url(&url)
            .await
            .map_err(|e| format!("URL rejected: {e}"))?;

        let id = uuid::Uuid::new_v4().to_string();
        let config = WebhookConfig {
            id: id.clone(),
            name,
            url,
            events,
            enabled: true,
            secret,
            delivery_count: 0,
            failure_count: 0,
        };
        self.webhooks.insert(id.clone(), config);
        Ok(id)
    }

    /// Event'e göre ilgili webhook'ları tetikle
    pub async fn fire_event(&self, event_type: &str, payload: serde_json::Value) {
        // Önce snapshot al ki delivery sırasında DashMap'i locklamayalım
        let targets: Vec<(String, String, Option<String>, String)> = self
            .webhooks
            .iter()
            .filter_map(|e| {
                let w = e.value();
                if !w.enabled {
                    return None;
                }
                if !w.events.iter().any(|s| s == event_type || s == "*") {
                    return None;
                }
                Some((w.id.clone(), w.url.clone(), w.secret.clone(), w.name.clone()))
            })
            .collect();

        for (id, url, secret, name) in targets {
            // Her gönderimden önce SSRF guard tekrar uygulanır (DNS rebinding'e karşı best-effort)
            if let Err(e) = url_guard::validate_outbound_url(&url).await {
                tracing::warn!(webhook = %name, error = %e, "Webhook URL rejected by SSRF guard");
                self.bump_failure(&id);
                continue;
            }

            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let body = serde_json::json!({
                "event": event_type,
                "source": "xiranet",
                "timestamp": timestamp,
                "data": payload,
            });
            let body_bytes = match serde_json::to_vec(&body) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let mut req = self
                .client
                .post(&url)
                .header("Content-Type", "application/json");

            if let Some(ref secret_value) = secret {
                // HMAC-SHA256 imzası: signed_payload = "{timestamp}.{body}"
                // Header: X-Webhook-Timestamp + X-Webhook-Signature (sha256=hex)
                let signed = format!("{}.{}", timestamp, String::from_utf8_lossy(&body_bytes));
                let sig = match HmacSha256::new_from_slice(secret_value.as_bytes()) {
                    Ok(mut mac) => {
                        mac.update(signed.as_bytes());
                        Some(format!("sha256={}", hex_encode(&mac.finalize().into_bytes())))
                    }
                    Err(_) => None,
                };
                if let Some(s) = sig {
                    req = req
                        .header("X-Webhook-Timestamp", timestamp.to_string())
                        .header("X-Webhook-Signature", s);
                }
            }

            match req.body(body_bytes).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        self.bump_delivery(&id);
                    } else {
                        let body = resp.text().await.unwrap_or_default();
                        tracing::warn!(
                            webhook = %name,
                            status = %status,
                            body = %crate::alerting::sanitize_for_log(&body, 256),
                            "Webhook returned non-success status"
                        );
                        self.bump_failure(&id);
                    }
                }
                Err(e) => {
                    self.bump_failure(&id);
                    tracing::warn!(webhook = %name, error = %e, "Webhook delivery failed");
                }
            }
        }
    }

    fn bump_delivery(&self, id: &str) {
        if let Some(mut e) = self.webhooks.get_mut(id) {
            e.delivery_count = e.delivery_count.saturating_add(1);
        }
    }

    fn bump_failure(&self, id: &str) {
        if let Some(mut e) = self.webhooks.get_mut(id) {
            e.failure_count = e.failure_count.saturating_add(1);
        }
    }

    /// Tüm webhook'ları listele (secret hariç)
    pub fn list(&self) -> Vec<serde_json::Value> {
        self.webhooks
            .iter()
            .map(|e| {
                let w = e.value();
                serde_json::json!({
                    "id": w.id,
                    "name": w.name,
                    "url": w.url,
                    "events": w.events,
                    "enabled": w.enabled,
                    "has_secret": w.secret.is_some(),
                    "delivery_count": w.delivery_count,
                    "failure_count": w.failure_count,
                })
            })
            .collect()
    }

    /// Webhook kaldır
    pub fn remove(&self, id: &str) -> bool {
        self.webhooks.remove(id).is_some()
    }

    pub fn count(&self) -> usize {
        self.webhooks.len()
    }
}

fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}
