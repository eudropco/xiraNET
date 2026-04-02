/// Event Bus — servisler arası pub/sub async event iletişimi
use dashmap::DashMap;
use tokio::sync::broadcast;
use std::sync::Arc;

pub struct EventBus {
    channels: DashMap<String, broadcast::Sender<Event>>,
    subscriptions: DashMap<String, Vec<String>>, // topic → [subscriber_ids]
    event_log: Arc<tokio::sync::RwLock<Vec<Event>>>,
    max_log_size: usize,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Event {
    pub id: String,
    pub topic: String,
    pub source: String,
    pub data: serde_json::Value,
    pub timestamp: u64,
}

impl EventBus {
    pub fn new(max_log_size: usize) -> Self {
        Self {
            channels: DashMap::new(),
            subscriptions: DashMap::new(),
            event_log: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            max_log_size,
        }
    }

    /// Event yayınla
    pub async fn publish(&self, topic: &str, source: &str, data: serde_json::Value) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let event = Event {
            id: id.clone(), topic: topic.to_string(),
            source: source.to_string(), data, timestamp: now,
        };

        // Channel'a gönder
        if let Some(sender) = self.channels.get(topic) {
            let _ = sender.send(event.clone());
        }

        // Log'a kaydet
        let mut log = self.event_log.write().await;
        log.push(event);
        let elen = log.len();
        if elen > self.max_log_size {
            log.drain(..elen - self.max_log_size);
        }

        tracing::debug!("Event published: {} on topic '{}'", id, topic);
        id
    }

    /// Topic'e subscribe ol
    pub fn subscribe(&self, topic: &str, subscriber_id: &str) -> broadcast::Receiver<Event> {
        let sender = self.channels.entry(topic.to_string())
            .or_insert_with(|| broadcast::channel(1024).0);
        let receiver = sender.subscribe();

        let mut subs = self.subscriptions.entry(topic.to_string()).or_default();
        if !subs.contains(&subscriber_id.to_string()) {
            subs.push(subscriber_id.to_string());
        }

        receiver
    }

    /// Topic'leri listele
    pub fn list_topics(&self) -> Vec<String> {
        self.channels.iter().map(|e| e.key().clone()).collect()
    }

    /// Subscription bilgisi
    pub fn topic_subscribers(&self, topic: &str) -> Vec<String> {
        self.subscriptions.get(topic)
            .map(|s| s.value().clone())
            .unwrap_or_default()
    }

    /// Son N event
    pub async fn recent_events(&self, limit: usize) -> Vec<Event> {
        let log = self.event_log.read().await;
        log.iter().rev().take(limit).cloned().collect()
    }

    /// Topic bazlı event sayısı
    pub async fn stats(&self) -> serde_json::Value {
        let log = self.event_log.read().await;
        let mut topic_counts = std::collections::HashMap::new();
        for event in log.iter() {
            *topic_counts.entry(event.topic.clone()).or_insert(0u64) += 1;
        }
        serde_json::json!({
            "total_events": log.len(),
            "topics": self.channels.len(),
            "topic_counts": topic_counts,
        })
    }
}
