use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// SLA Monitoring — servis başına uptime %, latency P99 tracking, SLA ihlali alertleri
pub struct SlaMonitor {
    services: DashMap<String, SlaMetrics>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SlaMetrics {
    pub service_name: String,
    pub total_checks: u64,
    pub successful_checks: u64,
    pub failed_checks: u64,
    pub uptime_percent: f64,
    pub latency_samples: Vec<f64>,
    pub latency_avg: f64,
    pub latency_p50: f64,
    pub latency_p95: f64,
    pub latency_p99: f64,
    pub latency_max: f64,
    pub sla_target_uptime: f64,     // e.g., 99.9
    pub sla_target_latency_ms: f64, // e.g., 200.0
    pub sla_violations: u64,
    pub last_check: u64,
}

impl SlaMonitor {
    pub fn new() -> Self {
        Self { services: DashMap::new() }
    }

    /// Servis için SLA hedefi belirle
    pub fn set_sla_target(&self, service_name: &str, uptime: f64, latency_ms: f64) {
        self.services.entry(service_name.to_string()).or_insert_with(|| SlaMetrics {
            service_name: service_name.to_string(),
            total_checks: 0, successful_checks: 0, failed_checks: 0,
            uptime_percent: 100.0, latency_samples: Vec::new(),
            latency_avg: 0.0, latency_p50: 0.0, latency_p95: 0.0, latency_p99: 0.0, latency_max: 0.0,
            sla_target_uptime: uptime, sla_target_latency_ms: latency_ms,
            sla_violations: 0, last_check: 0,
        }).sla_target_uptime = uptime;
    }

    /// Health check sonucu kaydet
    pub fn record_check(&self, service_name: &str, success: bool, latency_ms: f64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut entry = self.services.entry(service_name.to_string()).or_insert_with(|| SlaMetrics {
            service_name: service_name.to_string(),
            total_checks: 0, successful_checks: 0, failed_checks: 0,
            uptime_percent: 100.0, latency_samples: Vec::new(),
            latency_avg: 0.0, latency_p50: 0.0, latency_p95: 0.0, latency_p99: 0.0, latency_max: 0.0,
            sla_target_uptime: 99.9, sla_target_latency_ms: 500.0,
            sla_violations: 0, last_check: 0,
        });

        let metrics = entry.value_mut();
        metrics.total_checks += 1;
        metrics.last_check = now;

        if success {
            metrics.successful_checks += 1;
            metrics.latency_samples.push(latency_ms);
            if metrics.latency_samples.len() > 1000 {
                metrics.latency_samples.drain(..500);
            }
        } else {
            metrics.failed_checks += 1;
        }

        // Uptime recalc
        if metrics.total_checks > 0 {
            metrics.uptime_percent = (metrics.successful_checks as f64 / metrics.total_checks as f64) * 100.0;
        }

        // Latency percentiles
        if !metrics.latency_samples.is_empty() {
            let mut sorted = metrics.latency_samples.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let len = sorted.len();
            metrics.latency_avg = sorted.iter().sum::<f64>() / len as f64;
            metrics.latency_p50 = sorted[len / 2];
            metrics.latency_p95 = sorted[(len as f64 * 0.95) as usize];
            metrics.latency_p99 = sorted[(len as f64 * 0.99) as usize];
            metrics.latency_max = sorted[len - 1];
        }

        // SLA violation check
        if metrics.uptime_percent < metrics.sla_target_uptime || (latency_ms > metrics.sla_target_latency_ms && success) {
            metrics.sla_violations += 1;
        }
    }

    /// Tüm SLA metriklerini al
    pub fn all_metrics(&self) -> Vec<SlaMetrics> {
        self.services.iter().map(|e| e.value().clone()).collect()
    }

    /// Servis SLA metrikleri
    pub fn get_metrics(&self, service_name: &str) -> Option<SlaMetrics> {
        self.services.get(service_name).map(|e| e.value().clone())
    }

    /// SLA ihlallerini kontrol et
    pub fn check_violations(&self) -> Vec<(String, String)> {
        let mut violations = Vec::new();
        for entry in self.services.iter() {
            let m = entry.value();
            if m.uptime_percent < m.sla_target_uptime {
                violations.push((m.service_name.clone(), format!("Uptime {:.2}% < target {:.1}%", m.uptime_percent, m.sla_target_uptime)));
            }
            if m.latency_p99 > m.sla_target_latency_ms {
                violations.push((m.service_name.clone(), format!("P99 {:.1}ms > target {:.0}ms", m.latency_p99, m.sla_target_latency_ms)));
            }
        }
        violations
    }
}
