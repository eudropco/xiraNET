//! Redis tabanlı XiraBus implementasyonu — pub/sub channel `xira:bus`.
//!
//! Single channel kullanıyoruz; her event'in `kind` discriminator'ı ile route.
//! Bu deploy operasyonunu kolaylaştırır (tek channel, tek subscriber).
//!
//! Connection failure → publish silent fail (counter tick'ler). Subscriber
//! task'ı disconnect olursa exponential backoff ile retry, app crash etmez.

use crate::bus::{BusEvent, EventDispatcher, XiraBus};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::sync::Arc;

const CHANNEL: &str = "xira:bus";

pub struct RedisBus {
    /// Publish için connection manager (auto-reconnect).
    conn: tokio::sync::Mutex<ConnectionManager>,
    /// Diagnostic — bus init sırasında verify edildi.
    url: String,
}

impl RedisBus {
    /// `redis://host:port[/db]` URL'inden bağlanır. Hata olursa caller decide eder
    /// (genelde fallback NoOpBus).
    pub async fn connect(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("client open: {e}"))?;
        let mgr = ConnectionManager::new(client)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        Ok(Self {
            conn: tokio::sync::Mutex::new(mgr),
            url: url.to_string(),
        })
    }

    /// Subscriber task'ını başlat. `dispatcher` gelen event'leri yerel state'e
    /// işler. Self-published event'ler de yayılır — handler'lar idempotent olmalı.
    pub fn spawn_subscriber(&self, dispatcher: Arc<EventDispatcher>) {
        let url = self.url.clone();
        tokio::spawn(async move {
            let mut backoff_secs = 1u64;
            loop {
                match Self::run_subscriber(&url, dispatcher.clone()).await {
                    Ok(()) => {
                        // PubSub channel kapanmış — yeniden bağlan
                        tracing::warn!("Redis bus subscriber stream ended, reconnecting in 1s");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        backoff_secs = 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            backoff_secs,
                            "Redis bus subscriber error, retrying"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(30);
                    }
                }
            }
        });
    }

    async fn run_subscriber(
        url: &str,
        dispatcher: Arc<EventDispatcher>,
    ) -> Result<(), String> {
        use futures_util::StreamExt;
        let client = redis::Client::open(url).map_err(|e| format!("client open: {e}"))?;
        // PubSub için dedicated connection (subscribe blocking)
        let mut pubsub = client
            .get_async_pubsub()
            .await
            .map_err(|e| format!("get_async_pubsub: {e}"))?;
        pubsub
            .subscribe(CHANNEL)
            .await
            .map_err(|e| format!("subscribe: {e}"))?;
        tracing::info!("Redis bus subscriber connected to channel '{CHANNEL}'");

        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "redis bus: payload decode failed");
                    continue;
                }
            };
            match serde_json::from_str::<BusEvent>(&payload) {
                Ok(evt) => dispatcher.dispatch(evt).await,
                Err(e) => {
                    tracing::warn!(error = %e, payload = %payload, "redis bus: event JSON decode failed");
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl XiraBus for RedisBus {
    async fn publish(&self, event: &BusEvent) {
        let payload = match serde_json::to_string(event) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "redis bus: event JSON encode failed");
                return;
            }
        };
        let mut conn = self.conn.lock().await;
        let result: redis::RedisResult<u64> = conn.publish(CHANNEL, payload).await;
        if let Err(e) = result {
            tracing::warn!(error = %e, "redis bus: publish failed");
            crate::metrics::DB_PERSIST_ERRORS
                .with_label_values(&["bus_publish"])
                .inc();
        }
    }

    fn kind(&self) -> &'static str {
        "redis"
    }
}
