use actix_web::{HttpResponse, HttpRequest};
use prometheus::{
    Encoder, TextEncoder,
    IntCounterVec, HistogramVec, IntGauge,
    register_int_counter_vec, register_histogram_vec, register_int_gauge,
};

lazy_static::lazy_static! {
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "xiranet_http_requests_total",
        "Total number of HTTP requests",
        &["method", "path", "status"]
    ).unwrap();

    pub static ref HTTP_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "xiranet_http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "path"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).unwrap();

    pub static ref ACTIVE_CONNECTIONS: IntGauge = register_int_gauge!(
        "xiranet_active_connections",
        "Number of active connections"
    ).unwrap();

    pub static ref SERVICES_TOTAL: IntGauge = register_int_gauge!(
        "xiranet_services_total",
        "Total registered services"
    ).unwrap();

    pub static ref SERVICES_UP: IntGauge = register_int_gauge!(
        "xiranet_services_up",
        "Number of services with UP status"
    ).unwrap();

    pub static ref SERVICES_DOWN: IntGauge = register_int_gauge!(
        "xiranet_services_down",
        "Number of services with DOWN status"
    ).unwrap();

    pub static ref CIRCUIT_BREAKER_OPENS: IntCounterVec = register_int_counter_vec!(
        "xiranet_circuit_breaker_opens_total",
        "Total circuit breaker open events",
        &["service"]
    ).unwrap();

    pub static ref CACHE_HITS: IntCounterVec = register_int_counter_vec!(
        "xiranet_cache_hits_total",
        "Cache hit count",
        &["type"]
    ).unwrap();

    pub static ref PROXY_ERRORS: IntCounterVec = register_int_counter_vec!(
        "xiranet_proxy_errors_total",
        "Proxy error count",
        &["service", "error_type"]
    ).unwrap();
}

/// Record a request metric
pub fn record_request(method: &str, path: &str, status: u16, duration_secs: f64) {
    let status_str = status.to_string();
    // Prefix-only path for cardinality control
    let metric_path = extract_prefix(path);

    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, &metric_path, &status_str])
        .inc();

    HTTP_REQUEST_DURATION
        .with_label_values(&[method, &metric_path])
        .observe(duration_secs);
}

/// Update service gauges
pub fn update_service_gauges(total: usize, up: usize, down: usize) {
    SERVICES_TOTAL.set(total as i64);
    SERVICES_UP.set(up as i64);
    SERVICES_DOWN.set(down as i64);
}

/// Extract prefix from path for metric labels (to avoid high cardinality)
fn extract_prefix(path: &str) -> String {
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() >= 2 {
        format!("/{}", parts[1])
    } else {
        path.to_string()
    }
}

/// GET /metrics — Prometheus scrape endpoint
pub async fn metrics_handler(_req: HttpRequest) -> HttpResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(()) => HttpResponse::Ok()
            .content_type("text/plain; version=0.0.4; charset=utf-8")
            .body(buffer),
        Err(e) => {
            tracing::error!("Failed to encode metrics: {}", e);
            HttpResponse::InternalServerError().body("Failed to encode metrics")
        }
    }
}
