//! Audit log remote sink — tamper-evident kayıtların DB dışına da yazılması için.
//!
//! Phase 3.2'de audit_log SQLite tablosuna UPDATE/DELETE engelleyen trigger'lar
//! eklendi. Ancak DROP/ALTER hâlâ mümkün ve DB tek node'da yaşıyor. Gerçek
//! tamper-evident için kayıtların DB dışına paralel yazılması gerek:
//!
//! - **FileSink**: JSON Lines append-only — log-rotation harici process (logrotate
//!   veya WORM volume) ile koordine. Process dump edemez, yalnız append.
//! - **HttpSink**: webhook (OTLP-friendly JSON) — uzak SIEM / log aggregator'a
//!   gönderir. Asenkron, queue-backed; yavaş uzak sink uygulama'yı yavaşlatmaz.
//!
//! Sink kararı `XiraConfig.audit.sink` config'den. Her ikisi de paralel
//! çalışabilir. Default: yok (sadece SQLite).

use crate::middleware::audit_log::AuditEntry;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Bir audit entry'yi async olarak forward eden sink. Hata durumunda metric
/// tick'ler + warn log; kayıp tolerans burada vardır.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    async fn write(&self, entry: &AuditEntry) -> Result<(), String>;
    fn name(&self) -> &str;
}

/// JSON Lines append-only file sink.
pub struct FileSink {
    path: PathBuf,
}

impl FileSink {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait::async_trait]
impl AuditSink for FileSink {
    async fn write(&self, entry: &AuditEntry) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let line = serde_json::to_string(entry).map_err(|e| format!("ser: {e}"))?;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| format!("open {}: {e}", self.path.display()))?;
        file.write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        file.write_all(b"\n")
            .await
            .map_err(|e| format!("nl: {e}"))?;
        Ok(())
    }

    fn name(&self) -> &str {
        "file"
    }
}

/// HTTP webhook sink — uzak SIEM / log aggregator'a JSON POST.
pub struct HttpSink {
    url: String,
    client: reqwest::Client,
    extra_headers: Vec<(String, String)>,
}

impl HttpSink {
    pub fn new(url: String, extra_headers: Vec<(String, String)>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .connect_timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            url,
            client,
            extra_headers,
        }
    }
}

#[async_trait::async_trait]
impl AuditSink for HttpSink {
    async fn write(&self, entry: &AuditEntry) -> Result<(), String> {
        // SSRF guard — webhook URL operator-controlled olsa bile metadata IP
        // gönderimini engelle.
        crate::alerting::url_guard::validate_outbound_url(&self.url)
            .await
            .map_err(|e| format!("url_guard: {e}"))?;

        let mut req = self.client.post(&self.url).json(entry);
        for (k, v) in &self.extra_headers {
            req = req.header(k, v);
        }
        let resp = req.send().await.map_err(|e| format!("send: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("status: {}", resp.status()));
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "http"
    }
}

/// Tüm sink'leri yöneten dispatcher. Audit entry'leri buffer'a yazar; bir
/// background task buffer'ı tüketir ve her sink'e paralel yazar.
///
/// Buffer dolarsa **eski entry'leri DROP eder** — uygulama'nın yavaşlamasını
/// engellemek için DESIGN trade-off. Drop sayısı counter'da görünür.
pub struct AuditDispatcher {
    tx: mpsc::Sender<AuditEntry>,
}

impl AuditDispatcher {
    /// `sinks` boş ise dispatcher pass-through olur (write hiçbir şey yapmaz).
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>, buffer_size: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<AuditEntry>(buffer_size.max(1));
        if sinks.is_empty() {
            return Self { tx };
        }
        tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                for sink in &sinks {
                    if let Err(e) = sink.write(&entry).await {
                        crate::metrics::DB_PERSIST_ERRORS
                            .with_label_values(&[&format!("audit_sink_{}", sink.name())])
                            .inc();
                        tracing::warn!(error = %e, sink = sink.name(), "audit sink write failed");
                    }
                }
            }
        });
        Self { tx }
    }

    /// Non-blocking enqueue. Buffer doluysa DROP — counter tick'ler.
    pub fn dispatch(&self, entry: AuditEntry) {
        if let Err(e) = self.tx.try_send(entry) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    crate::metrics::DB_PERSIST_ERRORS
                        .with_label_values(&["audit_sink_buffer_full"])
                        .inc();
                }
                mpsc::error::TrySendError::Closed(_) => {
                    // Receiver kapandı — sessiz drop.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditEntry {
        AuditEntry {
            timestamp: "2026-05-14T00:00:00Z".to_string(),
            ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            status: 200,
            user_agent: "test".to_string(),
            api_key_preview: None,
            request_id: "req-1".to_string(),
            duration_ms: 1.5,
            body_size: 0,
            response_size: 100,
        }
    }

    #[tokio::test]
    async fn file_sink_appends_jsonl() {
        let tmp = std::env::temp_dir().join(format!(
            "xira-audit-test-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let sink = FileSink::new(tmp.clone());
        sink.write(&sample()).await.unwrap();
        sink.write(&sample()).await.unwrap();
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("/test"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn empty_dispatcher_drops_entry_without_panic() {
        let d = AuditDispatcher::new(vec![], 10);
        d.dispatch(sample()); // no panic
    }
}
