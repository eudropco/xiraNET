use actix_web::{HttpRequest, HttpResponse};
use prometheus::{
    core::Collector, Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts,
    TextEncoder,
};

/// Global Prometheus registry'ye kaydet — duplicate ise unregistered fallback dön.
/// Bu modül binary'deki `src/metrics/mod.rs` ile aynı isimde metrikler tanımlar.
/// `lazy_static! + register_*!().unwrap()` çağırırsak ikinci `unwrap` panik atar.
/// Hem standalone hem de gömülü kullanım için defansif olmamız gerekiyor.
fn try_register_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let opts = Opts::new(name, help);
    let cv = IntCounterVec::new(opts, labels).expect("metric construction must succeed");
    let _ = prometheus::default_registry().register(Box::new(cv.clone()) as Box<dyn Collector>);
    cv
}

fn try_register_histogram_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: Vec<f64>,
) -> HistogramVec {
    let opts = HistogramOpts::new(name, help).buckets(buckets);
    let hv = HistogramVec::new(opts, labels).expect("metric construction must succeed");
    let _ = prometheus::default_registry().register(Box::new(hv.clone()) as Box<dyn Collector>);
    hv
}

fn try_register_int_gauge(name: &str, help: &str) -> IntGauge {
    let opts = Opts::new(name, help);
    let g = IntGauge::with_opts(opts).expect("metric construction must succeed");
    let _ = prometheus::default_registry().register(Box::new(g.clone()) as Box<dyn Collector>);
    g
}

lazy_static::lazy_static! {
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = try_register_counter_vec(
        "xiranet_http_requests_total",
        "Total number of HTTP requests",
        &["method", "path", "status"]
    );

    pub static ref HTTP_REQUEST_DURATION: HistogramVec = try_register_histogram_vec(
        "xiranet_http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "path"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    );

    pub static ref ACTIVE_CONNECTIONS: IntGauge = try_register_int_gauge(
        "xiranet_active_connections",
        "Number of active connections"
    );

    pub static ref SERVICES_TOTAL: IntGauge = try_register_int_gauge(
        "xiranet_services_total",
        "Total registered services"
    );

    pub static ref SERVICES_UP: IntGauge = try_register_int_gauge(
        "xiranet_services_up",
        "Number of services with UP status"
    );

    pub static ref SERVICES_DOWN: IntGauge = try_register_int_gauge(
        "xiranet_services_down",
        "Number of services with DOWN status"
    );

    pub static ref CIRCUIT_BREAKER_OPENS: IntCounterVec = try_register_counter_vec(
        "xiranet_circuit_breaker_opens_total",
        "Total circuit breaker open events",
        &["service"]
    );

    pub static ref CACHE_HITS: IntCounterVec = try_register_counter_vec(
        "xiranet_cache_hits_total",
        "Cache hit count",
        &["type"]
    );

    pub static ref PROXY_ERRORS: IntCounterVec = try_register_counter_vec(
        "xiranet_proxy_errors_total",
        "Proxy error count",
        &["service", "error_type"]
    );
}

/// Record a request metric
pub fn record_request(method: &str, path: &str, status: u16, duration_secs: f64) {
    let status_str = status.to_string();
    let metric_path = extract_prefix(path);

    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, &metric_path, &status_str])
        .inc();

    HTTP_REQUEST_DURATION
        .with_label_values(&[method, &metric_path])
        .observe(duration_secs);
}

pub fn update_service_gauges(total: usize, up: usize, down: usize) {
    SERVICES_TOTAL.set(total as i64);
    SERVICES_UP.set(up as i64);
    SERVICES_DOWN.set(down as i64);
}

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
