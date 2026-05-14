use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use dashmap::DashMap;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

/// IP bazlı rate limiting (sliding-fixed-window token bucket).
///
/// v3.0 audit fix'leri (Yarı A, madde 3–5, 12, 13, 14):
/// - **Shared `Arc<DashMap>`**: Eski sürüm her Actix worker'da ayrı map
///   yaratıyordu → effective rate = config × workers. Şimdi map RateLimiter
///   struct'ında, tüm worker'lar aynı bucket'ı paylaşır.
/// - **X-Forwarded-For desteği**: `trust_xff` config flag açıksa client IP
///   XFF'in ilk hop'undan alınır (reverse proxy/LB arkasında doğru).
/// - **Eviction**: Her create'te bir background task `now - 2 * window` öncesi
///   entry'leri purges; IPv6 /64 rotating attacker OOM riskini kapatır.
///   Limiter Drop edildiğinde `Weak` upgrade-fail → task çıkar.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    max_requests: AtomicU32,
    window_secs: AtomicU64,
    trust_xff: AtomicBool,
    /// Tek paylaşılan map — tüm worker'lar buradan okur/yazar.
    limits: DashMap<String, RateLimitEntry>,
}

struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self::with_options(max_requests, window_secs, false)
    }

    pub fn with_options(max_requests: u32, window_secs: u64, trust_xff: bool) -> Self {
        let inner = Arc::new(Inner {
            max_requests: AtomicU32::new(max_requests.max(1)),
            window_secs: AtomicU64::new(window_secs.max(1)),
            trust_xff: AtomicBool::new(trust_xff),
            limits: DashMap::new(),
        });
        spawn_evictor(Arc::downgrade(&inner));
        Self { inner }
    }

    pub fn set_limits(&self, max_requests: u32, window_secs: u64) {
        self.inner
            .max_requests
            .store(max_requests.max(1), Ordering::Relaxed);
        self.inner
            .window_secs
            .store(window_secs.max(1), Ordering::Relaxed);
    }

    pub fn set_trust_xff(&self, value: bool) {
        self.inner.trust_xff.store(value, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u32, u64) {
        (
            self.inner.max_requests.load(Ordering::Relaxed),
            self.inner.window_secs.load(Ordering::Relaxed),
        )
    }

    /// Test/observability — şu an map'te kaç bucket var?
    pub fn bucket_count(&self) -> usize {
        self.inner.limits.len()
    }
}

/// Periyodik prune — `2 * window` üzerinden geçmiş entry'leri sil. Weak
/// upgrade fail → tüm RateLimiter clone'ları drop edildi, task çıkar.
fn spawn_evictor(weak: Weak<Inner>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let inner = match weak.upgrade() {
                Some(i) => i,
                None => return, // limiter dropped
            };
            let window = inner.window_secs.load(Ordering::Relaxed).max(1);
            let now = Instant::now();
            let stale = std::time::Duration::from_secs(window * 2);
            inner
                .limits
                .retain(|_, entry| now.duration_since(entry.window_start) < stale);
        }
    });
}

/// Client IP extract — `trust_xff` aktifse `X-Forwarded-For`'un ilk hop'unu
/// kullanır (LB/proxy'nin ekleyeceği orijinal client), yoksa peer_addr.
/// **NOT**: Bu trusted proxy mantığı içermez. XFF header'ı client tarafından
/// spoof edilebilir; `trust_xff` SADECE doğrudan public exposure ALTINDAKİ
/// proxy varsa açılmalı. README'de uyarı var.
fn client_ip(req: &ServiceRequest, trust_xff: bool) -> String {
    if trust_xff {
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                if let Some(first) = s.split(',').next() {
                    let candidate = first.trim();
                    if !candidate.is_empty() {
                        return candidate.to_string();
                    }
                }
            }
        }
    }
    req.peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = RateLimiterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimiterMiddleware {
            service,
            inner: self.inner.clone(),
        }))
    }
}

pub struct RateLimiterMiddleware<S> {
    service: S,
    inner: Arc<Inner>,
}

impl<S, B> Service<ServiceRequest> for RateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let trust_xff = self.inner.trust_xff.load(Ordering::Relaxed);
        let ip = client_ip(&req, trust_xff);

        let now = Instant::now();
        let max_requests = self.inner.max_requests.load(Ordering::Relaxed).max(1);
        let window_duration =
            std::time::Duration::from_secs(self.inner.window_secs.load(Ordering::Relaxed).max(1));

        let mut entry = self.inner.limits.entry(ip.clone()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) > window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;

        if entry.count > max_requests {
            let remaining = window_duration
                .checked_sub(now.duration_since(entry.window_start))
                .unwrap_or_default();

            drop(entry);

            crate::metrics::AUTH_REJECTS
                .with_label_values(&["rate_limited"])
                .inc();
            tracing::warn!("Rate limit exceeded for IP: {}", ip);
            return Box::pin(async move {
                let response = HttpResponse::TooManyRequests()
                    .insert_header(("Retry-After", remaining.as_secs().to_string()))
                    .json(serde_json::json!({
                        "error": "Rate limit exceeded",
                        "retry_after_secs": remaining.as_secs()
                    }));
                Ok(req.into_response(response).map_into_right_body())
            });
        }

        drop(entry);

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_web::test]
    async fn limits_shared_across_clones() {
        // Aynı limiter clone edildiğinde aynı bucket map'i paylaşır.
        let lim = RateLimiter::new(2, 60);
        let req = test::TestRequest::default()
            .peer_addr("1.2.3.4:1000".parse().unwrap())
            .to_srv_request();
        // İlk request — 1
        let ip = client_ip(&req, false);
        lim.inner.limits.insert(
            ip.clone(),
            RateLimitEntry {
                count: 1,
                window_start: Instant::now(),
            },
        );
        let lim2 = lim.clone();
        assert_eq!(lim2.bucket_count(), 1, "clone must share map");
    }

    #[actix_web::test]
    async fn xff_first_hop_used_when_trusted() {
        let req = test::TestRequest::default()
            .insert_header(("x-forwarded-for", "203.0.113.1, 10.0.0.1, 127.0.0.1"))
            .peer_addr("10.0.0.99:1000".parse().unwrap())
            .to_srv_request();
        assert_eq!(client_ip(&req, true), "203.0.113.1");
        assert_eq!(client_ip(&req, false), "10.0.0.99");
    }

    #[actix_web::test]
    async fn xff_empty_falls_back_to_peer() {
        let req = test::TestRequest::default()
            .insert_header(("x-forwarded-for", ""))
            .peer_addr("10.0.0.99:1000".parse().unwrap())
            .to_srv_request();
        assert_eq!(client_ip(&req, true), "10.0.0.99");
    }
}
