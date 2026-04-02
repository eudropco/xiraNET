use reqwest::Client;
use std::time::Duration;

/// Configurable retry logic with exponential backoff
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
            backoff_multiplier,
        }
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

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                tracing::debug!(
                    "Retry attempt {}/{} for {} (delay: {:?})",
                    attempt, self.max_retries, url, delay
                );
                tokio::time::sleep(delay).await;
                delay = Duration::from_millis(
                    (delay.as_millis() as f64 * self.backoff_multiplier) as u64
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
                    if status.is_server_error() && attempt < self.max_retries {
                        tracing::warn!(
                            "Got {} from {} (attempt {}/{}), retrying...",
                            status, url, attempt + 1, self.max_retries
                        );
                        last_error = None;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    // Connection error, timeout — retry edilebilir
                    if e.is_connect() || e.is_timeout() {
                        tracing::warn!(
                            "Request failed for {} (attempt {}/{}): {}",
                            url, attempt + 1, self.max_retries, e
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
