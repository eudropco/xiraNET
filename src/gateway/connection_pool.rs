use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Connection pool manager — upstream bağlantılarını yeniden kullanır
pub struct ConnectionPool {
    client: Client,
    pool_size: usize,
    timeout: Duration,
    stats: Arc<RwLock<PoolStats>>,
}

#[derive(Default, Clone)]
pub struct PoolStats {
    pub total_connections: u64,
    pub reused_connections: u64,
    pub failed_connections: u64,
}

impl ConnectionPool {
    pub fn new(pool_size: usize, timeout_secs: u64, keep_alive_secs: u64) -> Self {
        let client = Client::builder()
            .pool_max_idle_per_host(pool_size)
            .pool_idle_timeout(Duration::from_secs(keep_alive_secs))
            .timeout(Duration::from_secs(timeout_secs))
            .tcp_keepalive(Duration::from_secs(30))
            .tcp_nodelay(true)
            .build()
            .expect("Failed to create connection pool");

        tracing::info!(
            "Connection pool initialized: size={}, timeout={}s, keepalive={}s",
            pool_size, timeout_secs, keep_alive_secs
        );

        Self {
            client,
            pool_size,
            timeout: Duration::from_secs(timeout_secs),
            stats: Arc::new(RwLock::new(PoolStats::default())),
        }
    }

    /// Pooled client'ı al — TCP bağlantısı yeniden kullanılır
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Pool istatistikleri
    pub async fn stats(&self) -> PoolStats {
        self.stats.read().await.clone()
    }

    pub fn pool_size(&self) -> usize {
        self.pool_size
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Bağlantı istatistiklerini güncelle
    pub async fn record_connection(&self, reused: bool) {
        let mut stats = self.stats.write().await;
        stats.total_connections += 1;
        if reused {
            stats.reused_connections += 1;
        }
    }

    pub async fn record_failure(&self) {
        let mut stats = self.stats.write().await;
        stats.failed_connections += 1;
    }
}
