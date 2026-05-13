use rand::Rng;
use reqwest::Client;
use std::time::Duration;

/// Configurable retry logic with exponential backoff + full jitter.
/// Idempotent (GET/HEAD/OPTIONS) ve istek bazında `Idempotency-Key` taşıyan
/// PUT/DELETE retry edilir. POST/PATCH gibi non-idempotent yöntemler
/// `Idempotency-Key` header'ı yoksa retry edilmez (duplicate side-effect riski).
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub backoff_multiplier: f64,
}

impl RetryPolicy {
    pub fn new(max_retries: u32, delay_ms: u64, backoff_multiplier: f64) -> Self {
        Self {
            max_retries,
            initial_delay: Duration::from_millis(delay_ms),
            backoff_multiplier: backoff_multiplier.max(1.0),
        }
    }

    pub fn method_is_retryable(method: &reqwest::Method) -> bool {
        matches!(
            *method,
            reqwest::Method::GET | reqwest::Method::HEAD | reqwest::Method::OPTIONS
        )
    }

    /// PUT/DELETE retry'ı için idempotency-key gerekli; POST/PATCH ile retry yok.
    fn is_request_retryable(
        method: &reqwest::Method,
        headers: &reqwest::header::HeaderMap,
    ) -> bool {
        if Self::method_is_retryable(method) {
            return true;
        }
        let has_idem_key = headers.contains_key("idempotency-key")
            || headers.contains_key("x-idempotency-key");
        matches!(
            *method,
            reqwest::Method::PUT | reqwest::Method::DELETE
        ) && has_idem_key
    }

    /// İsteği retry policy ile gönder
    pub async fn execute(
        &self,
        client: &Client,
        method: reqwest::Method,
        url: &str,
        headers: reqwest::header::HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut last_error = None;
        let mut delay = self.initial_delay;
        let retryable_method = Self::is_request_retryable(&method, &headers);

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                // Full jitter: 0..=delay aralığında uyu (thundering herd koruması)
                let jitter_ms = if delay.as_millis() > 0 {
                    rand::thread_rng().gen_range(0..=delay.as_millis() as u64)
                } else {
                    0
                };
                let actual_delay = Duration::from_millis(jitter_ms);
                tracing::debug!(
                    "Retry attempt {}/{} for {} (delay: {:?}, jittered from {:?})",
                    attempt,
                    self.max_retries,
                    url,
                    actual_delay,
                    delay
                );
                tokio::time::sleep(actual_delay).await;
                delay = Duration::from_millis(
                    (delay.as_millis() as f64 * self.backoff_multiplier) as u64,
                );
            }

            let mut request = client.request(method.clone(), url);

            for (key, value) in headers.iter() {
                request = request.header(key, value);
            }

            if let Some(ref b) = body {
                request = request.body(b.clone());
            }

            match request.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    // 5xx hataları retry edilebilir
                    if retryable_method && status.is_server_error() && attempt < self.max_retries {
                        tracing::warn!(
                            "Got {} from {} (attempt {}/{}), retrying...",
                            status,
                            url,
                            attempt + 1,
                            self.max_retries
                        );
                        last_error = None;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    // Connection error, timeout — retry edilebilir
                    if retryable_method
                        && (e.is_connect() || e.is_timeout())
                        && attempt < self.max_retries
                    {
                        tracing::warn!(
                            "Request failed for {} (attempt {}/{}): {}",
                            url,
                            attempt + 1,
                            self.max_retries,
                            e
                        );
                        last_error = Some(e);
                        continue;
                    }
                    // Diğer hatalar retry edilemez
                    return Err(e);
                }
            }
        }

        Err(last_error.expect("Should have at least one error"))
    }
}

#[cfg(test)]
mod tests {
    use super::RetryPolicy;

    #[test]
    fn test_only_safe_methods_are_retryable() {
        assert!(RetryPolicy::method_is_retryable(&reqwest::Method::GET));
        assert!(RetryPolicy::method_is_retryable(&reqwest::Method::HEAD));
        assert!(RetryPolicy::method_is_retryable(&reqwest::Method::OPTIONS));
        assert!(!RetryPolicy::method_is_retryable(&reqwest::Method::POST));
        assert!(!RetryPolicy::method_is_retryable(&reqwest::Method::PATCH));
        assert!(!RetryPolicy::method_is_retryable(&reqwest::Method::DELETE));
    }

    #[test]
    fn put_delete_retried_only_with_idempotency_key() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let empty = HeaderMap::new();
        assert!(!RetryPolicy::is_request_retryable(&reqwest::Method::PUT, &empty));
        assert!(!RetryPolicy::is_request_retryable(&reqwest::Method::DELETE, &empty));

        let mut with_key = HeaderMap::new();
        with_key.insert("idempotency-key", HeaderValue::from_static("abc"));
        assert!(RetryPolicy::is_request_retryable(&reqwest::Method::PUT, &with_key));
        assert!(RetryPolicy::is_request_retryable(&reqwest::Method::DELETE, &with_key));

        // POST/PATCH idempotency-key olsa bile retry yok (semantik garanti yok)
        assert!(!RetryPolicy::is_request_retryable(&reqwest::Method::POST, &with_key));
    }
}
