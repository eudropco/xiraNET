/// Webhook Registry — servis event'lerini webhook'lara otomatik bildir
use dashmap::DashMap;
use reqwest::Client;
use std::time::Duration;

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
                .build()
                .unwrap(),
        }
    }

    /// Webhook kaydet
    pub fn register(&self, name: String, url: String, events: Vec<String>, secret: Option<String>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let config = WebhookConfig {
            id: id.clone(),
            name, url, events, enabled: true, secret,
            delivery_count: 0, failure_count: 0,
        };
        self.webhooks.insert(id.clone(), config);
        id
    }

    /// Event'e göre ilgili webhook'ları tetikle
    pub async fn fire_event(&self, event_type: &str, payload: serde_json::Value) {
        for mut entry in self.webhooks.iter_mut() {
            let webhook = entry.value_mut();
            if !webhook.enabled { continue; }
            if !webhook.events.contains(&event_type.to_string()) && !webhook.events.contains(&"*".to_string()) {
                continue;
            }

            let body = serde_json::json!({
                "event": event_type,
                "source": "xiranet",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "data": payload,
            });

            let mut req = self.client.post(&webhook.url).json(&body);
            if let Some(ref secret) = webhook.secret {
                // HMAC-style signature
                req = req.header("X-Webhook-Secret", secret.as_str());
            }

            match req.send().await {
                Ok(_) => webhook.delivery_count += 1,
                Err(e) => {
                    webhook.failure_count += 1;
                    tracing::warn!("Webhook delivery failed ({}): {}", webhook.name, e);
                }
            }
        }
    }

    /// Tüm webhook'ları listele
    pub fn list(&self) -> Vec<WebhookConfig> {
        self.webhooks.iter().map(|e| e.value().clone()).collect()
    }

    /// Webhook kaldır
    pub fn remove(&self, id: &str) -> bool {
        self.webhooks.remove(id).is_some()
    }

    pub fn count(&self) -> usize {
        self.webhooks.len()
    }
}
