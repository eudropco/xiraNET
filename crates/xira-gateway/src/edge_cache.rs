/// Edge caching — ETag/If-None-Match, 304 Not Modified, conditional GET support
use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct EdgeCache {
    entries: DashMap<String, EdgeCacheEntry>,
    max_entries: usize,
    enabled: bool,
}

#[derive(Clone)]
pub struct EdgeCacheEntry {
    pub etag: String,
    pub body: Vec<u8>,
    pub content_type: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub created_at: u64,
    pub ttl_secs: u64,
    pub hits: u64,
}

pub enum CacheDecision {
    /// Tam response döndür (cache hit)
    Hit(EdgeCacheEntry),
    /// 304 Not Modified döndür
    NotModified { etag: String },
    /// Cache miss — upstream'e git
    Miss,
}

impl EdgeCache {
    pub fn new(max_entries: usize, enabled: bool) -> Self {
        Self {
            entries: DashMap::new(),
            max_entries,
            enabled,
        }
    }

    /// Request'i cache'e karşı kontrol et
    pub fn check(&self, cache_key: &str, if_none_match: Option<&str>) -> CacheDecision {
        if !self.enabled {
            return CacheDecision::Miss;
        }

        if let Some(mut entry) = self.entries.get_mut(cache_key) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            // TTL expired?
            if now > entry.created_at + entry.ttl_secs {
                drop(entry);
                self.entries.remove(cache_key);
                return CacheDecision::Miss;
            }

            entry.hits += 1;

            // ETag conditional check
            if let Some(client_etag) = if_none_match {
                if client_etag == entry.etag || client_etag == format!("\"{}\"", entry.etag) {
                    return CacheDecision::NotModified { etag: entry.etag.clone() };
                }
            }

            return CacheDecision::Hit(entry.clone());
        }

        CacheDecision::Miss
    }

    /// Response'u cache'e yaz
    pub fn store(&self, cache_key: String, body: Vec<u8>, content_type: String, status: u16, headers: Vec<(String, String)>, ttl_secs: u64) -> String {
        // Eviction if needed
        if self.entries.len() >= self.max_entries {
            // En eski entry'yi kaldır
            if let Some(oldest_key) = self.entries.iter().min_by_key(|e| e.value().created_at).map(|e| e.key().clone()) {
                self.entries.remove(&oldest_key);
            }
        }

        // ETag oluştur
        let hash = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            body.hash(&mut hasher);
            format!("{:x}", hasher.finish())
        };

        let entry = EdgeCacheEntry {
            etag: hash.clone(),
            body,
            content_type,
            status,
            headers,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            ttl_secs,
            hits: 0,
        };

        self.entries.insert(cache_key, entry);
        hash
    }

    /// Cache istatistikleri
    pub fn stats(&self) -> serde_json::Value {
        let total_hits: u64 = self.entries.iter().map(|e| e.value().hits).sum();
        serde_json::json!({
            "entries": self.entries.len(),
            "max_entries": self.max_entries,
            "total_hits": total_hits,
            "enabled": self.enabled,
        })
    }

    pub fn clear(&self) {
        self.entries.clear();
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}
