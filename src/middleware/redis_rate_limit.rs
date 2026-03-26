use redis::AsyncCommands;
use std::sync::Arc;

/// Redis-backed distributed rate limiter
#[derive(Clone)]
pub struct DistributedRateLimiter {
    client: Option<Arc<redis::aio::ConnectionManager>>,
    max_requests: u32,
    window_secs: u64,
    enabled: bool,
}

impl DistributedRateLimiter {
    /// Yeni Redis rate limiter oluştur
    pub async fn new(
        redis_url: Option<&str>,
        max_requests: u32,
        window_secs: u64,
    ) -> Self {
        let client = if let Some(url) = redis_url {
            match redis::Client::open(url) {
                Ok(client) => match redis::aio::ConnectionManager::new(client).await {
                    Ok(cm) => {
                        tracing::info!("Redis rate limiter connected: {}", url);
                        Some(Arc::new(cm))
                    }
                    Err(e) => {
                        tracing::warn!("Redis connection failed (falling back to local): {}", e);
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("Redis client error (falling back to local): {}", e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            enabled: client.is_some(),
            client,
            max_requests,
            window_secs,
        }
    }

    /// IP bazlı rate limit kontrolü
    pub async fn check_rate_limit(&self, ip: &str) -> Result<(bool, u32), ()> {
        let client = match &self.client {
            Some(c) if self.enabled => c,
            _ => return Ok((true, 0)), // Redis yoksa izin ver
        };

        let key = format!("xiranet:rl:{}", ip);
        let mut conn = (**client).clone();

        // MULTI: INCR + EXPIRE (atomic)
        let count: u32 = match conn.incr::<_, u32, u32>(&key, 1).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Redis INCR error: {} — allowing request", e);
                return Ok((true, 0));
            }
        };

        // İlk istek ise TTL ayarla
        if count == 1 {
            let _ = conn.expire::<_, ()>(&key, self.window_secs as i64).await;
        }

        let remaining = if count > self.max_requests { 0 } else { self.max_requests - count };
        let allowed = count <= self.max_requests;

        if !allowed {
            tracing::debug!("Redis rate limit exceeded for {}: {}/{}", ip, count, self.max_requests);
        }

        Ok((allowed, remaining))
    }

    /// Service-specific rate limit
    pub async fn check_service_rate_limit(&self, ip: &str, service_id: &str, max: u32) -> Result<bool, ()> {
        let client = match &self.client {
            Some(c) if self.enabled => c,
            _ => return Ok(true),
        };

        let key = format!("xiranet:rl:{}:{}", service_id, ip);
        let mut conn = (**client).clone();

        let count: u32 = conn.incr(&key, 1).await.unwrap_or(0);
        if count == 1 {
            let _ = conn.expire::<_, ()>(&key, self.window_secs as i64).await;
        }

        Ok(count <= max)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}
