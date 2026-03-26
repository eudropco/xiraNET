use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    cached_at: Instant,
    ttl: Duration,
}

impl CachedResponse {
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// LRU-based response cache with TTL
pub struct ResponseCache {
    cache: Mutex<LruCache<String, CachedResponse>>,
    ttl: Duration,
    enabled: bool,
}

impl ResponseCache {
    pub fn new(max_entries: usize, ttl_secs: u64, enabled: bool) -> Self {
        let capacity = NonZeroUsize::new(max_entries.max(1)).unwrap();
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            ttl: Duration::from_secs(ttl_secs),
            enabled,
        }
    }

    /// Cache'den response al
    pub fn get(&self, key: &str) -> Option<(u16, Vec<(String, String)>, Vec<u8>)> {
        if !self.enabled {
            return None;
        }

        let mut cache = self.cache.lock().unwrap();
        if let Some(entry) = cache.get(key) {
            if entry.is_expired() {
                cache.pop(key);
                return None;
            }
            return Some((entry.status, entry.headers.clone(), entry.body.clone()));
        }
        None
    }

    /// Response'u cache'le
    pub fn put(&self, key: String, status: u16, headers: Vec<(String, String)>, body: Vec<u8>) {
        if !self.enabled {
            return;
        }

        // Sadece başarılı GET isteklerini cache'le
        if status < 200 || status >= 300 {
            return;
        }

        let mut cache = self.cache.lock().unwrap();
        cache.put(key, CachedResponse {
            status,
            headers,
            body,
            cached_at: Instant::now(),
            ttl: self.ttl,
        });
    }

    /// Cache key oluştur (method + path + query)
    pub fn make_key(method: &str, path: &str, query: &str) -> String {
        if query.is_empty() {
            format!("{}:{}", method, path)
        } else {
            format!("{}:{}?{}", method, path, query)
        }
    }

    /// Cache'i temizle
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    /// Cache istatistikleri
    pub fn stats(&self) -> serde_json::Value {
        let cache = self.cache.lock().unwrap();
        serde_json::json!({
            "enabled": self.enabled,
            "entries": cache.len(),
            "capacity": cache.cap().get(),
            "ttl_secs": self.ttl.as_secs(),
        })
    }
}
