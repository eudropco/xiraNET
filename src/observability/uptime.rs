/// Uptime / Status Page — public status page with service health
use dashmap::DashMap;

pub struct UptimePage {
    services: DashMap<String, UptimeService>,
    global_message: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct UptimeService {
    pub name: String,
    pub status: ServiceStatus,
    pub uptime_percent: f64,
    pub response_time_ms: f64,
    pub last_check: u64,
    pub history: Vec<StatusPoint>, // last 90 data points
}

#[derive(Clone, Debug, serde::Serialize, PartialEq)]
pub enum ServiceStatus { Operational, Degraded, PartialOutage, MajorOutage, Maintenance }

#[derive(Clone, Debug, serde::Serialize)]
pub struct StatusPoint { pub timestamp: u64, pub status: ServiceStatus, pub response_ms: f64 }

impl Default for UptimePage {
    fn default() -> Self {
        Self::new()
    }
}

impl UptimePage {
    pub fn new() -> Self {
        Self { services: DashMap::new(), global_message: String::new() }
    }

    /// Servis durumunu güncelle
    pub fn update(&self, name: &str, status: ServiceStatus, response_ms: f64) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut svc = self.services.entry(name.to_string()).or_insert(UptimeService {
            name: name.to_string(), status: ServiceStatus::Operational,
            uptime_percent: 100.0, response_time_ms: 0.0, last_check: 0, history: Vec::new(),
        });

        svc.status = status.clone();
        svc.response_time_ms = response_ms;
        svc.last_check = now;
        svc.history.push(StatusPoint { timestamp: now, status, response_ms });
        let hist_len = svc.history.len();
        if hist_len > 90 { svc.history.drain(..hist_len - 90); }

        // Uptime recalc
        let total = svc.history.len();
        let operational = svc.history.iter().filter(|p| p.status == ServiceStatus::Operational).count();
        svc.uptime_percent = if total > 0 { (operational as f64 / total as f64) * 100.0 } else { 100.0 };
    }

    /// Public status page JSON
    pub fn render(&self) -> serde_json::Value {
        let services: Vec<serde_json::Value> = self.services.iter().map(|e| {
            serde_json::json!({
                "name": e.value().name,
                "status": format!("{:?}", e.value().status),
                "uptime": format!("{:.2}%", e.value().uptime_percent),
                "response_ms": e.value().response_time_ms,
                "last_check": e.value().last_check,
            })
        }).collect();

        let all_operational = self.services.iter().all(|s| s.value().status == ServiceStatus::Operational);

        serde_json::json!({
            "status": if all_operational { "All Systems Operational" } else { "Issues Detected" },
            "message": self.global_message,
            "services": services,
            "updated_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        })
    }

    pub fn set_message(&mut self, msg: String) { self.global_message = msg; }
}
