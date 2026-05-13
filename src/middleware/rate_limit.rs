use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use dashmap::DashMap;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// IP bazlı rate limiting (token-bucket)
#[derive(Clone)]
pub struct RateLimiter {
    config: Arc<RateLimiterConfig>,
}

struct RateLimiterConfig {
    max_requests: AtomicU32,
    window_secs: AtomicU64,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            config: Arc::new(RateLimiterConfig {
                max_requests: AtomicU32::new(max_requests.max(1)),
                window_secs: AtomicU64::new(window_secs.max(1)),
            }),
        }
    }

    pub fn set_limits(&self, max_requests: u32, window_secs: u64) {
        self.config
            .max_requests
            .store(max_requests.max(1), Ordering::Relaxed);
        self.config
            .window_secs
            .store(window_secs.max(1), Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u32, u64) {
        (
            self.config.max_requests.load(Ordering::Relaxed),
            self.config.window_secs.load(Ordering::Relaxed),
        )
    }
}

struct RateLimitEntry {
    count: u32,
    window_start: Instant,
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
            limits: Arc::new(DashMap::new()),
            config: self.config.clone(),
        }))
    }
}

pub struct RateLimiterMiddleware<S> {
    service: S,
    limits: Arc<DashMap<String, RateLimitEntry>>,
    config: Arc<RateLimiterConfig>,
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
        let ip = req
            .peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let now = Instant::now();
        let max_requests = self.config.max_requests.load(Ordering::Relaxed).max(1);
        let window_duration =
            std::time::Duration::from_secs(self.config.window_secs.load(Ordering::Relaxed).max(1));

        let mut entry = self.limits.entry(ip.clone()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Pencere süresi dolduysa sıfırla
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
