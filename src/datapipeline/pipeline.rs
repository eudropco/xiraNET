/// Data Pipeline — CDC (change detection), analytics sink, batch export
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct DataPipeline {
    cdc_watchers: Arc<RwLock<Vec<CdcWatcher>>>,
    analytics_buffer: Arc<RwLock<Vec<AnalyticsEvent>>>,
    buffer_size: usize,
    sink_url: Option<String>,
    client: reqwest::Client,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CdcWatcher {
    pub id: String,
    pub endpoint: String, // monitored path
    pub webhook_url: String,
    pub last_response_hash: String,
    pub change_count: u64,
    pub enabled: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AnalyticsEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub path: String,
    pub method: String,
    pub status: u16,
    pub duration_ms: f64,
    pub ip: String,
    pub user_agent: String,
    pub body_size: u64,
}

impl DataPipeline {
    pub fn new(buffer_size: usize, sink_url: Option<String>) -> Self {
        Self {
            cdc_watchers: Arc::new(RwLock::new(Vec::new())),
            analytics_buffer: Arc::new(RwLock::new(Vec::new())),
            buffer_size,
            sink_url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    /// CDC watcher ekle
    pub async fn add_watcher(&self, endpoint: String, webhook_url: String) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.cdc_watchers.write().await.push(CdcWatcher {
            id: id.clone(),
            endpoint,
            webhook_url,
            last_response_hash: String::new(),
            change_count: 0,
            enabled: true,
        });
        id
    }

    /// CDC check — three-phase lock disiplini: snapshot → drop lock → I/O →
    /// reacquire & merge. Bir slow upstream tüm CDC pipeline'ını veya admin
    /// `list_watchers` read'ini kilitlemez. (Eski versiyon RwLock write guard'ı
    /// HTTP round-trip + webhook POST boyunca tutuyordu — admin UI takılıyordu.)
    pub async fn check_changes(&self) {
        // 1) Snapshot
        let snapshot: Vec<(String, String, String, String)> = {
            let watchers = self.cdc_watchers.read().await;
            watchers
                .iter()
                .filter(|w| w.enabled)
                .map(|w| {
                    (
                        w.id.clone(),
                        w.endpoint.clone(),
                        w.webhook_url.clone(),
                        w.last_response_hash.clone(),
                    )
                })
                .collect()
        };

        // 2) I/O — paralel HTTP, lock yok
        let mut handles = Vec::with_capacity(snapshot.len());
        for (id, endpoint, webhook, last_hash) in snapshot {
            let client = self.client.clone();
            handles.push(tokio::spawn(async move {
                let body = match client.get(&endpoint).send().await {
                    Ok(resp) => match resp.text().await {
                        Ok(b) => b,
                        Err(_) => return (id, None, None),
                    },
                    Err(_) => return (id, None, None),
                };
                let hash = {
                    use sha2::{Digest, Sha256};
                    let digest = Sha256::digest(body.as_bytes());
                    let mut out = String::with_capacity(64);
                    for b in digest {
                        use std::fmt::Write;
                        let _ = write!(out, "{b:02x}");
                    }
                    out
                };
                let changed = !last_hash.is_empty() && hash != last_hash;
                if changed {
                    let _ = client
                        .post(&webhook)
                        .json(&serde_json::json!({
                            "event": "data_changed",
                            "endpoint": endpoint,
                            "timestamp": std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        }))
                        .send()
                        .await;
                }
                (id, Some(hash), Some(changed))
            }));
        }

        // 3) Merge — kısa write-lock altında hash + change_count update
        let mut updates: Vec<(String, String, bool)> = Vec::new();
        for h in handles {
            if let Ok((id, Some(hash), Some(changed))) = h.await {
                updates.push((id, hash, changed));
            }
        }
        if updates.is_empty() {
            return;
        }
        let mut watchers = self.cdc_watchers.write().await;
        for (id, hash, changed) in updates {
            if let Some(w) = watchers.iter_mut().find(|w| w.id == id) {
                w.last_response_hash = hash;
                if changed {
                    w.change_count = w.change_count.saturating_add(1);
                    tracing::info!(
                        "CDC change detected: {} (change #{})",
                        w.endpoint,
                        w.change_count
                    );
                }
            }
        }
    }

    /// Analytics event buffer'a ekle
    pub async fn record_event(&self, event: AnalyticsEvent) {
        let mut buffer = self.analytics_buffer.write().await;
        buffer.push(event);

        // Buffer dolduğunda flush
        if buffer.len() >= self.buffer_size {
            self.flush_buffer(&mut buffer).await;
        }
    }

    /// Buffer'ı sink'e flush et
    async fn flush_buffer(&self, buffer: &mut Vec<AnalyticsEvent>) {
        if let Some(ref url) = self.sink_url {
            let events: Vec<_> = std::mem::take(buffer);
            let payload = serde_json::json!({
                "source": "xiranet",
                "event_count": events.len(),
                "events": events,
                "flushed_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            });

            match self.client.post(url).json(&payload).send().await {
                Ok(_) => tracing::info!("Analytics flushed: {} events → {}", events.len(), url),
                Err(e) => tracing::warn!("Analytics flush failed: {}", e),
            }
        } else {
            let count = buffer.len();
            buffer.clear();
            tracing::debug!(
                "Analytics buffer cleared ({} events, no sink configured)",
                count
            );
        }
    }

    /// Manuel export
    pub async fn export(&self) -> Vec<AnalyticsEvent> {
        self.analytics_buffer.read().await.clone()
    }

    pub async fn list_watchers(&self) -> Vec<CdcWatcher> {
        self.cdc_watchers.read().await.clone()
    }
}
