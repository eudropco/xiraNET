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
            client: reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build().unwrap(),
        }
    }

    /// CDC watcher ekle
    pub async fn add_watcher(&self, endpoint: String, webhook_url: String) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.cdc_watchers.write().await.push(CdcWatcher {
            id: id.clone(), endpoint, webhook_url,
            last_response_hash: String::new(), change_count: 0, enabled: true,
        });
        id
    }

    /// CDC check — response'u karşılaştır, değişmişse webhook'la
    pub async fn check_changes(&self) {
        let mut watchers = self.cdc_watchers.write().await;
        for watcher in watchers.iter_mut() {
            if !watcher.enabled { continue; }

            if let Ok(resp) = self.client.get(&watcher.endpoint).send().await {
                if let Ok(body) = resp.text().await {
                    let hash = {
                        use std::hash::{Hash, Hasher};
                        let mut h = std::collections::hash_map::DefaultHasher::new();
                        body.hash(&mut h);
                        format!("{:x}", h.finish())
                    };

                    if !watcher.last_response_hash.is_empty() && hash != watcher.last_response_hash {
                        watcher.change_count += 1;
                        tracing::info!("CDC change detected: {} (change #{})", watcher.endpoint, watcher.change_count);

                        // Webhook bildir
                        let _ = self.client.post(&watcher.webhook_url)
                            .json(&serde_json::json!({
                                "event": "data_changed",
                                "endpoint": watcher.endpoint,
                                "change_number": watcher.change_count,
                                "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                            }))
                            .send().await;
                    }

                    watcher.last_response_hash = hash;
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
            tracing::debug!("Analytics buffer cleared ({} events, no sink configured)", count);
        }
    }

    /// Manuel export
    pub async fn export(&self) -> Vec<AnalyticsEvent> {
        self.analytics_buffer.read().await.clone()
    }

    pub async fn list_watchers(&self) -> Vec<CdcWatcher> { self.cdc_watchers.read().await.clone() }
}
