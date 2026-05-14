//! Multi-node coordination bus — session invalidation ve WAF rule broadcast
//! için ortak pub/sub abstraction'ı.
//!
//! Tasarım kararları:
//! - Async fire-and-forget publish; receiver hatalı/down ise app yavaşlamaz
//! - Subscriber **opsiyonel** background task; bus disabled ise tüm hot path'lar
//!   no-op
//! - NoOpBus (default) — single-node deploy için sıfır overhead
//! - RedisBus — `redis::aio::PubSub` üzerine; connection-manager ile reconnect
//!
//! Channel'lar:
//! - `xira:session:invalidate`  — `SessionInvalidate { user_id?, hashed_token? }`
//! - `xira:waf:rule:added`      — `WafRuleAdded { id, pattern, label }`
//! - `xira:waf:rule:removed`    — `WafRuleRemoved { id }`

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum BusEvent {
    /// Bu kullanıcının tüm session'larını local cache'ten temizle.
    SessionInvalidateUser { user_id: String },
    /// Tek bir hashed token'i invalidate et.
    SessionInvalidateToken { hashed_token: String },
    /// WAF custom rule eklendi — config-driven hot-reload sırasında değil,
    /// admin endpoint çağrısı sonrası yayılır.
    WafRuleAdded {
        id: u64,
        pattern: String,
        label: String,
    },
    /// WAF custom rule silindi.
    WafRuleRemoved { id: u64 },
}

#[async_trait]
pub trait XiraBus: Send + Sync {
    /// Event'i broadcast et. Fire-and-forget; başarısızlık warn'a düşer.
    async fn publish(&self, event: &BusEvent);
    /// Bus tipi (no-op vs redis) — observability için.
    fn kind(&self) -> &'static str;
    /// Subscriber background task'ını başlat. NoOpBus için no-op döner.
    /// Bu method trait'te olduğu için main.rs ayrı bir RedisBus instance'ı
    /// oluşturmak zorunda kalmıyor — v3.0 audit Yarı B madde 25.
    fn spawn_subscriber(&self, dispatcher: Arc<EventDispatcher>);
}

/// Multi-node coordination kapalıyken (single-node) kullanılan no-op.
pub struct NoOpBus;

#[async_trait]
impl XiraBus for NoOpBus {
    async fn publish(&self, _event: &BusEvent) {}
    fn kind(&self) -> &'static str {
        "noop"
    }
    fn spawn_subscriber(&self, _dispatcher: Arc<EventDispatcher>) {
        // single-node: subscriber yok, dispatcher unused
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_publish_does_nothing() {
        let bus = NoOpBus;
        bus.publish(&BusEvent::SessionInvalidateUser {
            user_id: "u1".into(),
        })
        .await;
        assert_eq!(bus.kind(), "noop");
    }

    #[test]
    fn bus_event_serde_roundtrip() {
        let evt = BusEvent::WafRuleAdded {
            id: 7,
            pattern: "evil".into(),
            label: "test".into(),
        };
        let s = serde_json::to_string(&evt).unwrap();
        let back: BusEvent = serde_json::from_str(&s).unwrap();
        match back {
            BusEvent::WafRuleAdded { id, pattern, label } => {
                assert_eq!(id, 7);
                assert_eq!(pattern, "evil");
                assert_eq!(label, "test");
            }
            _ => panic!("wrong variant"),
        }
    }
}

pub mod redis_bus;

/// Bus event handler — subscriber callback. Sessions ve WAF state'i mutate eder.
#[async_trait]
pub trait BusEventHandler: Send + Sync {
    async fn handle(&self, event: BusEvent);
}

/// Tüm event'leri kayıt edilen handler'lara dispatch et — handler list owned.
pub struct EventDispatcher {
    handlers: Vec<Arc<dyn BusEventHandler>>,
}

impl EventDispatcher {
    pub fn new(handlers: Vec<Arc<dyn BusEventHandler>>) -> Self {
        Self { handlers }
    }

    pub async fn dispatch(&self, event: BusEvent) {
        for h in &self.handlers {
            h.handle(event.clone()).await;
        }
    }
}
