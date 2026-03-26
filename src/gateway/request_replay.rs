/// Request Replay — SQLite loglarından replay
use crate::registry::storage::SqliteStorage;
use std::sync::Arc;

pub struct RequestReplay {
    storage: Arc<SqliteStorage>,
}

impl RequestReplay {
    pub fn new(storage: Arc<SqliteStorage>) -> Self {
        Self { storage }
    }

    /// Log ID'ye göre request'i replay et
    pub async fn replay_by_id(&self, log_id: &str) -> Result<ReplayResult, String> {
        // SQLite'dan log'u çek
        let logs: Vec<serde_json::Value> = self.storage.get_recent_logs(100).map_err(|e| format!("DB error: {}", e))?;
        let log: &serde_json::Value = logs.iter()
            .find(|l: &&serde_json::Value| l.get("id").and_then(|v| v.as_str()) == Some(log_id))
            .ok_or("Log entry not found")?;

        let method: &str = log.get("method").and_then(|m| m.as_str()).unwrap_or("GET");
        let url: &str = log.get("url").and_then(|u| u.as_str()).unwrap_or("");

        if url.is_empty() {
            return Err("Log entry has no URL".to_string());
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;

        let start = std::time::Instant::now();
        let result = match method {
            "POST" => client.post(url).send().await,
            "PUT" => client.put(url).send().await,
            "DELETE" => client.delete(url).send().await,
            _ => client.get(url).send().await,
        };

        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(resp) => Ok(ReplayResult {
                status: resp.status().as_u16(),
                duration_ms,
                body_size: resp.content_length().unwrap_or(0),
                original_method: method.to_string(),
                original_url: url.to_string(),
            }),
            Err(e) => Err(format!("Replay failed: {}", e)),
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct ReplayResult {
    pub status: u16,
    pub duration_ms: f64,
    pub body_size: u64,
    pub original_method: String,
    pub original_url: String,
}
