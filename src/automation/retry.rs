/// Retry Manager — exponential backoff ile otomatik tekrarlama
use std::time::Duration;

pub struct RetryManager;

#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
    pub retry_on_status: Vec<u16>, // e.g., [500, 502, 503]
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            retry_on_status: vec![500, 502, 503, 504],
        }
    }
}

impl RetryManager {
    /// Exponential backoff ile HTTP request tekrarla
    pub async fn execute_with_retry(
        client: &reqwest::Client,
        url: &str,
        method: &str,
        body: Option<&str>,
        policy: &RetryPolicy,
    ) -> Result<RetryResult, String> {
        let mut attempt = 0;
        let mut last_error = String::new();
        let mut total_duration = 0.0;

        loop {
            attempt += 1;
            let start = std::time::Instant::now();

            let result = match method.to_uppercase().as_str() {
                "POST" => {
                    let mut req = client.post(url);
                    if let Some(b) = body { req = req.body(b.to_string()); }
                    req.send().await
                },
                "PUT" => client.put(url).send().await,
                "DELETE" => client.delete(url).send().await,
                _ => client.get(url).send().await,
            };

            let duration = start.elapsed().as_secs_f64() * 1000.0;
            total_duration += duration;

            match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if policy.retry_on_status.contains(&status) && attempt < policy.max_attempts {
                        let delay = calculate_delay(attempt, policy);
                        tracing::warn!("Retry {}/{}: HTTP {} (waiting {}ms)", attempt, policy.max_attempts, status, delay);
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        continue;
                    }
                    return Ok(RetryResult {
                        status, attempts: attempt, total_duration_ms: total_duration,
                        success: resp.status().is_success(),
                    });
                }
                Err(e) => {
                    last_error = e.to_string();
                    if attempt >= policy.max_attempts {
                        return Err(format!("All {} attempts failed. Last: {}", policy.max_attempts, last_error));
                    }
                    let delay = calculate_delay(attempt, policy);
                    tracing::warn!("Retry {}/{}: {} (waiting {}ms)", attempt, policy.max_attempts, last_error, delay);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct RetryResult {
    pub status: u16,
    pub attempts: u32,
    pub total_duration_ms: f64,
    pub success: bool,
}

fn calculate_delay(attempt: u32, policy: &RetryPolicy) -> u64 {
    let delay = (policy.initial_delay_ms as f64 * policy.backoff_multiplier.powi(attempt as i32 - 1)) as u64;
    delay.min(policy.max_delay_ms)
}
