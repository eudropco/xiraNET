use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Load balancing stratejileri
#[derive(Debug, Clone)]
pub enum LoadBalanceStrategy {
    RoundRobin,
    Random,
    LeastConnections,
}

impl LoadBalanceStrategy {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "random" => Self::Random,
            "least-connections" | "least_connections" => Self::LeastConnections,
            _ => Self::RoundRobin,
        }
    }
}

/// Load balancer manager
#[derive(Clone)]
pub struct LoadBalancer {
    counters: Arc<DashMap<Uuid, AtomicUsize>>,
    connections: Arc<DashMap<String, AtomicUsize>>,
}

impl Default for LoadBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(DashMap::new()),
            connections: Arc::new(DashMap::new()),
        }
    }

    /// Upstreams listesinden bir upstream seç
    pub fn select_upstream(
        &self,
        service_id: &Uuid,
        upstreams: &[String],
        strategy: &LoadBalanceStrategy,
    ) -> String {
        if upstreams.is_empty() {
            return String::new();
        }

        if upstreams.len() == 1 {
            return upstreams[0].clone();
        }

        match strategy {
            LoadBalanceStrategy::RoundRobin => {
                let counter = self.counters
                    .entry(*service_id)
                    .or_insert(AtomicUsize::new(0));
                let idx = counter.fetch_add(1, Ordering::Relaxed) % upstreams.len();
                upstreams[idx].clone()
            }
            LoadBalanceStrategy::Random => {
                let idx = rand_index(upstreams.len());
                upstreams[idx].clone()
            }
            LoadBalanceStrategy::LeastConnections => {
                let mut min_connections = usize::MAX;
                let mut selected = &upstreams[0];

                for upstream in upstreams {
                    let conn_count = self.connections
                        .get(upstream)
                        .map(|c| c.load(Ordering::Relaxed))
                        .unwrap_or(0);
                    if conn_count < min_connections {
                        min_connections = conn_count;
                        selected = upstream;
                    }
                }

                selected.clone()
            }
        }
    }

    /// Bağlantı sayacını artır
    pub fn acquire_connection(&self, upstream: &str) {
        self.connections
            .entry(upstream.to_string())
            .or_insert(AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Bağlantı sayacını azalt (atomic)
    pub fn release_connection(&self, upstream: &str) {
        if let Some(counter) = self.connections.get(upstream) {
            // Atomic fetch_update: underflow'u önle
            let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
                if prev > 0 { Some(prev - 1) } else { None }
            });
        }
    }
}

/// Random index (hash-based, no external crate)
fn rand_index(max: usize) -> usize {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    std::time::Instant::now().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    (hasher.finish() as usize) % max
}
