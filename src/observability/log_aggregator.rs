/// Log Aggregator — upstream'lerden log topla, indexle, ara
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct LogAggregator {
    logs: Arc<RwLock<Vec<LogEntry>>>,
    index: DashMap<String, Vec<usize>>, // keyword → [log indices]
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
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum LogLevel { Trace, Debug, Info, Warn, Error, Fatal }

#[derive(Clone, Debug, serde::Serialize)]
pub struct LogSource {
    pub name: String,
    pub url: String,
    pub log_count: u64,
    pub last_received: u64,
}

impl LogAggregator {
    pub fn new(max_entries: usize) -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            index: DashMap::new(),
            max_entries,
            sources: DashMap::new(),
        }
    }

    /// Log entry ekle
    pub async fn ingest(&self, source: &str, level: LogLevel, message: String, metadata: std::collections::HashMap<String, String>) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut logs = self.logs.write().await;
        let id = logs.len();

        // Index keywords
        for word in message.split_whitespace() {
            if word.len() > 2 {
                self.index.entry(word.to_lowercase()).or_insert(Vec::new()).push(id);
            }
        }

        logs.push(LogEntry { id, timestamp: now, source: source.to_string(), level, message, metadata });

        // Eviction
        let log_len = logs.len();
        if log_len > self.max_entries {
            logs.drain(..log_len / 2);
        }

        // Source tracking
        let mut src = self.sources.entry(source.to_string()).or_insert(LogSource {
            name: source.to_string(), url: String::new(), log_count: 0, last_received: 0,
        });
        src.log_count += 1;
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
        logs.iter().rev().filter(|l| &l.level == level).take(limit).cloned().collect()
    }

    /// Source'a göre filtrele
    pub async fn by_source(&self, source: &str, limit: usize) -> Vec<LogEntry> {
        let logs = self.logs.read().await;
        logs.iter().rev().filter(|l| l.source == source).take(limit).cloned().collect()
    }

    /// Son N log
    pub async fn recent(&self, limit: usize) -> Vec<LogEntry> {
        let logs = self.logs.read().await;
        logs.iter().rev().take(limit).cloned().collect()
    }

    /// İstatistikler
    pub async fn stats(&self) -> serde_json::Value {
        let logs = self.logs.read().await;
        let mut level_counts = std::collections::HashMap::new();
        for log in logs.iter() {
            *level_counts.entry(format!("{:?}", log.level)).or_insert(0u64) += 1;
        }
        serde_json::json!({
            "total_logs": logs.len(),
            "sources": self.sources.len(),
            "level_distribution": level_counts,
        })
    }

    pub fn list_sources(&self) -> Vec<LogSource> {
        self.sources.iter().map(|e| e.value().clone()).collect()
    }
}
