use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    cached_at: Instant,
    /// Upstream'in `Vary` header'ından çıkarılan başlık adları (lowercase).
    /// Boş ise vary etkisi yok.
    vary_on: Vec<String>,
}

fn lock_or_recover<'a, T>(m: &'a Mutex<T>) -> std::sync::MutexGuard<'a, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

impl CachedResponse {
    fn is_expired(&self, ttl_secs: u64) -> bool {
        self.cached_at.elapsed() >= std::time::Duration::from_secs(ttl_secs)
    }
}

/// LRU-based response cache with TTL
pub struct ResponseCache {
    cache: Mutex<LruCache<String, CachedResponse>>,
    ttl_secs: AtomicU64,
    enabled: AtomicBool,
}

impl ResponseCache {
    pub fn new(max_entries: usize, ttl_secs: u64, enabled: bool) -> Self {
        let capacity = NonZeroUsize::new(max_entries.max(1)).unwrap();
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            ttl_secs: AtomicU64::new(ttl_secs),
            enabled: AtomicBool::new(enabled),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            self.clear();
        }
    }

    pub fn set_ttl_secs(&self, ttl_secs: u64) {
        self.ttl_secs.store(ttl_secs, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs.load(Ordering::Relaxed)
    }

    /// Cache'den response al. `request_headers` Vary-aware lookup için kullanılır.
    /// Eğer cached entry'nin `Vary` header'ı varsa, sadece istekteki ilgili
    /// header değerleri eşleşirse hit dön.
    #[allow(clippy::type_complexity)]
    pub fn get(
        &self,
        key: &str,
        request_headers: &[(String, String)],
    ) -> Option<(u16, Vec<(String, String)>, Vec<u8>)> {
        if !self.is_enabled() {
            return None;
        }

        let ttl_secs = self.ttl_secs();
        let mut cache = lock_or_recover(&self.cache);
        if let Some(entry) = cache.get(key) {
            if entry.is_expired(ttl_secs) {
                cache.pop(key);
                return None;
            }
            // Vary kontrolü: entry'deki vary_on her header için, cached vs request
            // değerleri eşleşmeli. Cached değeri entry.headers içinde aranır
            // (sunucu cevabında dönen değer client'ın gönderdiği değer olmalı —
            // bu yaklaşım Vary contract'ı için sufficient değil ama poisoning'i azaltır;
            // doğru implementasyon her variant için ayrı entry tutmaktır).
            if !entry.vary_on.is_empty() {
                let request_etag = compute_vary_etag(&entry.vary_on, request_headers);
                let cached_etag = compute_vary_etag(&entry.vary_on, &entry.headers);
                if request_etag != cached_etag {
                    return None;
                }
            }
            return Some((entry.status, entry.headers.clone(), entry.body.clone()));
        }
        None
    }

    /// Response'u cache'le. `Vary` header'ında listelenenleri saklarız.
    /// Cookie/Authorization üzerinde Vary edilen response'lar cache'lenmez —
    /// per-user içerik shared cache'te paylaşılmamalı.
    pub fn put(&self, key: String, status: u16, headers: Vec<(String, String)>, body: Vec<u8>) {
        if !self.is_enabled() {
            return;
        }

        // Sadece başarılı GET isteklerini cache'le
        if !(200..300).contains(&status) {
            return;
        }

        // Vary parsing
        let vary_on = extract_vary(&headers);

        // Vary: * → asla cache'leme
        if vary_on.iter().any(|v| v == "*") {
            return;
        }
        // Per-user içeriği cache'leme — shared cache poisoning riski
        if vary_on
            .iter()
            .any(|v| v == "cookie" || v == "authorization")
        {
            return;
        }
        // Cache-Control kontrolü: no-store/private respect et
        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("cache-control") {
                let lower = v.to_ascii_lowercase();
                if lower.contains("no-store") || lower.contains("private") {
                    return;
                }
            }
            if k.eq_ignore_ascii_case("set-cookie") {
                // Set-Cookie'li response shared cache'te tehlikeli
                return;
            }
        }

        let mut cache = lock_or_recover(&self.cache);
        cache.put(
            key,
            CachedResponse {
                status,
                headers,
                body,
                cached_at: Instant::now(),
                vary_on,
            },
        );
    }

    /// Cache key oluştur (method + path + query)
    pub fn make_key(method: &str, path: &str, query: &str) -> String {
        if query.is_empty() {
            format!("{method}:{path}")
        } else {
            format!("{method}:{path}?{query}")
        }
    }

    /// Cache'i temizle
    pub fn clear(&self) {
        let mut cache = lock_or_recover(&self.cache);
        cache.clear();
    }

    /// Cache istatistikleri
    pub fn stats(&self) -> serde_json::Value {
        let cache = lock_or_recover(&self.cache);
        serde_json::json!({
            "enabled": self.is_enabled(),
            "entries": cache.len(),
            "capacity": cache.cap().get(),
            "ttl_secs": self.ttl_secs(),
        })
    }
}

fn extract_vary(headers: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("vary") {
            for token in v.split(',') {
                let t = token.trim().to_ascii_lowercase();
                if !t.is_empty() && !out.contains(&t) {
                    out.push(t);
                }
            }
        }
    }
    out
}

fn compute_vary_etag(vary_on: &[String], headers: &[(String, String)]) -> String {
    let mut parts = Vec::with_capacity(vary_on.len());
    for name in vary_on {
        let value = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        parts.push(format!("{name}={value}"));
    }
    parts.join("|")
}

#[cfg(test)]
mod tests {
    use super::ResponseCache;

    #[test]
    fn test_disabling_cache_evicts_entries() {
        let cache = ResponseCache::new(16, 60, true);
        cache.put("GET:/api".to_string(), 200, vec![], b"ok".to_vec());
        assert!(cache.get("GET:/api", &[]).is_some());

        cache.set_enabled(false);

        assert!(cache.get("GET:/api", &[]).is_none());
    }

    #[test]
    fn test_ttl_update_expires_existing_entries() {
        let cache = ResponseCache::new(16, 60, true);
        cache.put("GET:/api".to_string(), 200, vec![], b"ok".to_vec());

        cache.set_ttl_secs(0);

        assert!(cache.get("GET:/api", &[]).is_none());
    }

    #[test]
    fn vary_cookie_response_is_not_cached() {
        let cache = ResponseCache::new(16, 60, true);
        cache.put(
            "GET:/api".to_string(),
            200,
            vec![("Vary".to_string(), "Cookie".to_string())],
            b"per-user".to_vec(),
        );
        assert!(cache.get("GET:/api", &[]).is_none());
    }

    #[test]
    fn vary_star_response_is_not_cached() {
        let cache = ResponseCache::new(16, 60, true);
        cache.put(
            "GET:/api".to_string(),
            200,
            vec![("Vary".to_string(), "*".to_string())],
            b"any".to_vec(),
        );
        assert!(cache.get("GET:/api", &[]).is_none());
    }

    #[test]
    fn set_cookie_response_is_not_cached() {
        let cache = ResponseCache::new(16, 60, true);
        cache.put(
            "GET:/api".to_string(),
            200,
            vec![("Set-Cookie".to_string(), "sid=abc".to_string())],
            b"x".to_vec(),
        );
        assert!(cache.get("GET:/api", &[]).is_none());
    }
}
