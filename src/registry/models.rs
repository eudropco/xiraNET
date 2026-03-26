use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServiceStatus {
    Up,
    Down,
    Unknown,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStatus::Up => write!(f, "UP"),
            ServiceStatus::Down => write!(f, "DOWN"),
            ServiceStatus::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub upstream: String,
    pub health_endpoint: String,
    pub status: ServiceStatus,
    pub registered_at: DateTime<Utc>,
    pub last_health_check: Option<DateTime<Utc>>,
    pub request_count: u64,
    /// Multiple upstreams for load balancing
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Load balance strategy: "round-robin", "weighted", "random"
    #[serde(default)]
    pub load_balance: Option<String>,
    /// API version tag
    #[serde(default)]
    pub version: Option<String>,
    /// JSON Schema for request validation
    #[serde(default)]
    pub validation_schema: Option<String>,
}

impl ServiceEntry {
    pub fn new(name: String, prefix: String, upstream: String, health_endpoint: String) -> Self {
        let prefix = if prefix.starts_with('/') { prefix } else { format!("/{}", prefix) };
        let prefix = prefix.trim_end_matches('/').to_string();

        Self {
            id: Uuid::new_v4(),
            name,
            prefix,
            upstream: upstream.trim_end_matches('/').to_string(),
            health_endpoint,
            status: ServiceStatus::Unknown,
            registered_at: Utc::now(),
            last_health_check: None,
            request_count: 0,
            upstreams: vec![],
            load_balance: None,
            version: None,
            validation_schema: None,
        }
    }

    /// Tüm upstream'leri al (ana upstream + ekstra upstreams)
    pub fn all_upstreams(&self) -> Vec<String> {
        let mut all = vec![self.upstream.clone()];
        for u in &self.upstreams {
            if !all.contains(u) {
                all.push(u.clone());
            }
        }
        all
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterServiceRequest {
    pub name: String,
    pub prefix: String,
    pub upstream: String,
    #[serde(default = "default_health_ep")]
    pub health_endpoint: String,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub load_balance: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub validation_schema: Option<String>,
}

fn default_health_ep() -> String {
    "/health".to_string()
}

#[derive(Debug, Serialize)]
pub struct ServiceListResponse {
    pub total: usize,
    pub services: Vec<ServiceEntry>,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_services: usize,
    pub services_up: usize,
    pub services_down: usize,
    pub services_unknown: usize,
    pub total_requests: u64,
    pub uptime_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_stats: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(message: impl Into<String>, data: T) -> Self {
        Self { success: true, message: message.into(), data: Some(data) }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self { success: false, message: message.into(), data: None }
    }
}
