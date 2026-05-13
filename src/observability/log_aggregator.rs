/// Log Aggregator — upstream'lerden log topla, indexle, ara
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Maksimum kelime uzunluğu — saldırgan log enjeksiyonu ile DashMap'i şişiremesin
const MAX_INDEXED_WORD_LEN: usize = 64;
/// Tek log entry'sinden alınacak maksimum unique kelime sayısı
const MAX_WORDS_PER_LOG: usize = 32;

pub struct LogAggregator {
    logs: Arc<RwLock<Vec<LogEntry>>>,
    /// keyword → [log id'leri]. Her ingest'te güncellenir; eviction sırasında prune edilir.
    index: Arc<DashMap<String, Vec<usize>>>,
    /// Bir sonraki log için global monotonik id
    next_id: Arc<std::sync::atomic::AtomicUsize>,
    /// Index'te tutulan en küçük log id (eviction watermark)
    min_kept_id: Arc<std::sync::atomic::AtomicUsize>,
    max_entries: usize,
    sources: DashMap<String, LogSource>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LogEntry {
    pub id: usize,
    pub timestamp: u64,
    pub source: String,
    pub level: LogLevel,
    pub message: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LogSource {
    pub name: String,
    pub url: String,
    pub log_count: u64,
    pub last_received: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// CR/LF/control karakterleri ve uzunluğu sınırla — log injection koruması.
fn sanitize_message(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(8192));
    for c in input.chars().take(8192) {
        match c {
            '\r' | '\n' | '\t' => out.push(' '),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

impl LogAggregator {
    pub fn new(max_entries: usize) -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            index: Arc::new(DashMap::new()),
            next_id: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            min_kept_id: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_entries: max_entries.max(1),
            sources: DashMap::new(),
        }
    }

    /// Log entry ekle
    pub async fn ingest(
        &self,
        source: &str,
        level: LogLevel,
        message: String,
        metadata: HashMap<String, String>,
    ) {
        let now = now_secs();
        let sanitized = sanitize_message(&message);

        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Index keywords — kelime uzunluğunu cap'le, unique kelime sayısını cap'le
        let mut seen_words: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for word in sanitized.split_whitespace() {
            if word.len() <= 2 || word.len() > MAX_INDEXED_WORD_LEN {
                continue;
            }
            let lower = word.to_lowercase();
            if !seen_words.insert(lower.clone()) {
                continue;
            }
            if seen_words.len() > MAX_WORDS_PER_LOG {
                break;
            }
            self.index.entry(lower).or_default().push(id);
        }

        let entry = LogEntry {
            id,
            timestamp: now,
            source: source.to_string(),
            level,
            message: sanitized,
            metadata,
        };

        let mut logs = self.logs.write().await;
        logs.push(entry);

        // Eviction: max_entries'i aşarsa eski yarıyı düş, index'i prune et
        if logs.len() > self.max_entries {
            let drop_count = logs.len() / 2;
            let cutoff_id = if drop_count < logs.len() {
                logs[drop_count - 1].id + 1
            } else {
                id + 1
            };
            logs.drain(..drop_count);
            drop(logs); // Lock'u bırak — index pruning ayrı

            // Index'ten silinen id'leri çıkar
            self.min_kept_id
                .store(cutoff_id, std::sync::atomic::Ordering::Relaxed);
            let mut empty_keys: Vec<String> = Vec::new();
            for mut entry in self.index.iter_mut() {
                entry.value_mut().retain(|&i| i >= cutoff_id);
                if entry.value().is_empty() {
                    empty_keys.push(entry.key().clone());
                }
            }
            for k in empty_keys {
                self.index.remove(&k);
            }
        }

        // Source tracking
        let mut src = self.sources.entry(source.to_string()).or_insert(LogSource {
            name: source.to_string(),
            url: String::new(),
            log_count: 0,
            last_received: 0,
        });
        src.log_count = src.log_count.saturating_add(1);
        src.last_received = now;
    }

    /// Full-text search
    pub async fn search(&self, query: &str, limit: usize) -> Vec<LogEntry> {
        let logs = self.logs.read().await;
        let query_lower = query.to_lowercase();

        logs.iter()
            .rev()
            .filter(|log| log.message.to_lowercase().contains(&query_lower))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Level'a göre filtrele
    pub async fn by_level(&self, level: &LogLevel, limit: usize) -> Vec<LogEntry> {
        let logs = self.logs.read().await;
        logs.iter()
            .rev()
            .filter(|l| &l.level == level)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Source'a göre filtrele
    pub async fn by_source(&self, source: &str, limit: usize) -> Vec<LogEntry> {
        let logs = self.logs.read().await;
        logs.iter()
            .rev()
            .filter(|l| l.source == source)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Son N log
    pub async fn recent(&self, limit: usize) -> Vec<LogEntry> {
        let logs = self.logs.read().await;
        logs.iter().rev().take(limit).cloned().collect()
    }

    /// İstatistikler
    pub async fn stats(&self) -> serde_json::Value {
        let logs = self.logs.read().await;
        let mut level_counts = HashMap::new();
        for log in logs.iter() {
            *level_counts
                .entry(format!("{:?}", log.level))
                .or_insert(0u64) += 1;
        }
        serde_json::json!({
            "total_logs": logs.len(),
            "indexed_keywords": self.index.len(),
            "sources": self.sources.len(),
            "level_distribution": level_counts,
        })
    }

    pub fn list_sources(&self) -> Vec<LogSource> {
        self.sources.iter().map(|e| e.value().clone()).collect()
    }
}
