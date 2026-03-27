/// Query Firewall — SQL query analizi, tehlikeli sorgu engelleme, slow query logging
use regex::Regex;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct QueryFirewall {
    blocked_patterns: Vec<Regex>,
    slow_threshold_ms: f64,
    slow_log: Arc<RwLock<Vec<SlowQuery>>>,
    stats: Arc<RwLock<QueryStats>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SlowQuery {
    pub query_preview: String,
    pub duration_ms: f64,
    pub source: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct QueryStats {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub slow_queries: u64,
    pub reads: u64,
    pub writes: u64,
}

pub enum QueryVerdict {
    Allow { is_read: bool },
    Block { reason: String },
}

impl QueryFirewall {
    pub fn new(slow_threshold_ms: f64) -> Self {
        Self {
            blocked_patterns: vec![
                Regex::new(r"(?i)\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)").unwrap(),
                Regex::new(r"(?i)\bALTER\s+TABLE\b.*\b(DROP|RENAME)\b").unwrap(),
                Regex::new(r"(?i)\bDELETE\s+FROM\s+\w+\s*$").unwrap(), // DELETE without WHERE
                Regex::new(r"(?i)\b(GRANT|REVOKE)\s+(ALL|SUPER|CREATE)").unwrap(),
                Regex::new(r"(?i)\bSHUTDOWN\b").unwrap(),
                Regex::new(r"(?i)\bLOAD\s+DATA\b").unwrap(),
                Regex::new(r"(?i)\bINTO\s+OUTFILE\b").unwrap(),
            ],
            slow_threshold_ms,
            slow_log: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(QueryStats::default())),
        }
    }

    /// Sorguyu kontrol et
    pub fn inspect(&self, query: &str) -> QueryVerdict {
        // Special check: UPDATE without WHERE (can't use negative lookahead in Rust regex)
        let upper = query.to_uppercase();
        if upper.contains("UPDATE") && upper.contains("SET") && !upper.contains("WHERE") {
            tracing::warn!("🛡️ Query blocked: {}...", &query[..query.len().min(80)]);
            return QueryVerdict::Block {
                reason: "UPDATE without WHERE clause detected".to_string(),
            };
        }

        for pattern in &self.blocked_patterns {
            if pattern.is_match(query) {
                tracing::warn!("🛡️ Query blocked: {}...", &query[..query.len().min(80)]);
                return QueryVerdict::Block {
                    reason: format!("Dangerous query pattern detected: {}", pattern.as_str()),
                };
            }
        }

        let is_read = query.trim_start().to_uppercase().starts_with("SELECT")
            || query.trim_start().to_uppercase().starts_with("SHOW")
            || query.trim_start().to_uppercase().starts_with("DESCRIBE")
            || query.trim_start().to_uppercase().starts_with("EXPLAIN");

        QueryVerdict::Allow { is_read }
    }

    /// Slow query kaydet
    pub async fn record_slow(&self, query: &str, duration_ms: f64, source: &str) {
        if duration_ms > self.slow_threshold_ms {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let mut log = self.slow_log.write().await;
            log.push(SlowQuery {
                query_preview: query[..query.len().min(200)].to_string(),
                duration_ms, source: source.to_string(), timestamp: now,
            });
            if log.len() > 500 { log.drain(..250); }

            let mut stats = self.stats.write().await;
            stats.slow_queries += 1;
        }
    }

    /// Query istatistiklerini kaydet
    pub async fn record_query(&self, is_read: bool) {
        let mut stats = self.stats.write().await;
        stats.total_queries += 1;
        if is_read { stats.reads += 1; } else { stats.writes += 1; }
    }

    /// Slow query log
    pub async fn get_slow_queries(&self, limit: usize) -> Vec<SlowQuery> {
        let log = self.slow_log.read().await;
        log.iter().rev().take(limit).cloned().collect()
    }

    /// İstatistikler
    pub async fn stats(&self) -> QueryStats {
        self.stats.read().await.clone()
    }
}

/// Read/Write Splitter — SELECT'leri replica'ya, yazmaları primary'ye
pub struct ReadWriteSplitter {
    pub primary: String,
    pub replicas: Vec<String>,
    current_replica: std::sync::atomic::AtomicUsize,
}

impl ReadWriteSplitter {
    pub fn new(primary: String, replicas: Vec<String>) -> Self {
        Self { primary, replicas, current_replica: std::sync::atomic::AtomicUsize::new(0) }
    }

    /// Sorguya göre target seç
    pub fn route(&self, is_read: bool) -> &str {
        if is_read && !self.replicas.is_empty() {
            let idx = self.current_replica.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.replicas.len();
            &self.replicas[idx]
        } else {
            &self.primary
        }
    }
}
