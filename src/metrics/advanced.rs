/// Advanced Metrics — per-service tracking, bandwidth, error rates, response code distribution
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct AdvancedMetrics {
    services: DashMap<String, ServiceMetrics>,
    global_bandwidth: BandwidthCounter,
}

#[derive(Debug, Default)]
pub struct ServiceMetrics {
    pub requests: AtomicU64,
    pub errors_4xx: AtomicU64,
    pub errors_5xx: AtomicU64,
    pub success_2xx: AtomicU64,
    pub redirect_3xx: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub total_latency_ms: AtomicU64, // sum for avg calc
}

#[derive(Debug, Default)]
pub struct BandwidthCounter {
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
}

impl Default for AdvancedMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvancedMetrics {
    pub fn new() -> Self {
        Self {
            services: DashMap::new(),
            global_bandwidth: BandwidthCounter::default(),
        }
    }

    /// Request kaydı
    pub fn record(&self, service_name: &str, status: u16, bytes_in: u64, bytes_out: u64, latency_ms: f64) {
        let entry = self.services.entry(service_name.to_string()).or_default();
        let m = entry.value();

        m.requests.fetch_add(1, Ordering::Relaxed);
        m.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        m.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        m.total_latency_ms.fetch_add(latency_ms as u64, Ordering::Relaxed);

        match status {
            200..=299 => m.success_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => m.redirect_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => m.errors_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => m.errors_5xx.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };

        self.global_bandwidth.total_bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.global_bandwidth.total_bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
    }

    /// Servis metrikleri
    pub fn get_service(&self, name: &str) -> Option<serde_json::Value> {
        self.services.get(name).map(|e| {
            let m = e.value();
            let reqs = m.requests.load(Ordering::Relaxed);
            let total_lat = m.total_latency_ms.load(Ordering::Relaxed);
            let e4 = m.errors_4xx.load(Ordering::Relaxed);
            let e5 = m.errors_5xx.load(Ordering::Relaxed);

            serde_json::json!({
                "requests": reqs,
                "avg_latency_ms": if reqs > 0 { total_lat as f64 / reqs as f64 } else { 0.0 },
                "status_codes": {
                    "2xx": m.success_2xx.load(Ordering::Relaxed),
                    "3xx": m.redirect_3xx.load(Ordering::Relaxed),
                    "4xx": e4,
                    "5xx": e5,
                },
                "error_rate": if reqs > 0 { (e4 + e5) as f64 / reqs as f64 } else { 0.0 },
                "bandwidth": {
                    "bytes_in": m.bytes_in.load(Ordering::Relaxed),
                    "bytes_out": m.bytes_out.load(Ordering::Relaxed),
                }
            })
        })
    }

    /// Tüm servislerin metrikleri
    pub fn all_services(&self) -> serde_json::Value {
        let services: Vec<serde_json::Value> = self.services.iter().map(|e| {
            let name = e.key().clone();
            let m = e.value();
            let reqs = m.requests.load(Ordering::Relaxed);
            let e4 = m.errors_4xx.load(Ordering::Relaxed);
            let e5 = m.errors_5xx.load(Ordering::Relaxed);
            serde_json::json!({
                "service": name,
                "requests": reqs,
                "2xx": m.success_2xx.load(Ordering::Relaxed),
                "3xx": m.redirect_3xx.load(Ordering::Relaxed),
                "4xx": e4, "5xx": e5,
                "error_rate": if reqs > 0 { (e4 + e5) as f64 / reqs as f64 } else { 0.0 },
                "bytes_in": m.bytes_in.load(Ordering::Relaxed),
                "bytes_out": m.bytes_out.load(Ordering::Relaxed),
            })
        }).collect();

        serde_json::json!({
            "services": services,
            "global_bandwidth": {
                "bytes_in": self.global_bandwidth.total_bytes_in.load(Ordering::Relaxed),
                "bytes_out": self.global_bandwidth.total_bytes_out.load(Ordering::Relaxed),
            }
        })
    }

    /// Error rate threshold alert kontrolü
    pub fn check_error_thresholds(&self, threshold: f64) -> Vec<(String, f64)> {
        self.services.iter().filter_map(|e| {
            let m = e.value();
            let reqs = m.requests.load(Ordering::Relaxed);
            if reqs == 0 { return None; }
            let errors = m.errors_4xx.load(Ordering::Relaxed) + m.errors_5xx.load(Ordering::Relaxed);
            let rate = errors as f64 / reqs as f64;
            if rate > threshold { Some((e.key().clone(), rate)) } else { None }
        }).collect()
    }
}
