pub mod advanced;
pub mod sla;
pub mod trace_collector;

use actix_web::{HttpRequest, HttpResponse};
use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
    Encoder, HistogramVec, IntCounter, IntCounterVec, IntGauge, TextEncoder,
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

    // ═══════════════════════════════════════════════════════════════
    // Security & persistence counters (v3.0 audit)
    // ═══════════════════════════════════════════════════════════════

    /// WAF tarafından bloke edilen request sayısı (rule başına).
    pub static ref WAF_BLOCKS: IntCounterVec = register_int_counter_vec!(
        "xiranet_waf_blocks_total",
        "Requests blocked by WAF, by rule",
        &["rule"]
    ).unwrap();

    /// WAF detect_only modunda tespit edilen ama bloke edilmeyen request'ler
    /// (audit trail — operatör tehdit yüzeyini gözlemleyebilsin).
    pub static ref WAF_DETECTS: IntCounterVec = register_int_counter_vec!(
        "xiranet_waf_detects_total",
        "Requests matched by WAF rules in detect_only mode (not blocked)",
        &["rule"]
    ).unwrap();

    /// SSRF guard tarafından reddedilen URL sayısı (kategori başına).
    pub static ref SSRF_REJECTS: IntCounterVec = register_int_counter_vec!(
        "xiranet_ssrf_rejects_total",
        "Outbound URLs rejected by SSRF guard, by reason category",
        &["category"]
    ).unwrap();

    /// Auth reject — kategori: missing_key, wrong_key, jwt_invalid, session_invalid, role_insufficient.
    pub static ref AUTH_REJECTS: IntCounterVec = register_int_counter_vec!(
        "xiranet_auth_rejects_total",
        "Authentication/authorization rejections, by category",
        &["category"]
    ).unwrap();

    /// SQLite persist hataları — tablo başına (audit_log, sessions, cron_jobs, registry vb.).
    pub static ref DB_PERSIST_ERRORS: IntCounterVec = register_int_counter_vec!(
        "xiranet_db_persist_errors_total",
        "SQLite persistence failures, by table",
        &["table"]
    ).unwrap();

    /// Session lifecycle event'ları — created, validated, invalidated, expired.
    pub static ref SESSION_EVENTS: IntCounterVec = register_int_counter_vec!(
        "xiranet_session_events_total",
        "Session lifecycle event counts",
        &["event"]
    ).unwrap();

    /// Bu node'daki aktif session sayısı (multi-node deploy'de Grafana panel'inde
    /// her node ayrı bar gösterir — sticky LB doğru çalışıyor mu doğrulamak için).
    pub static ref SESSIONS_ACTIVE: IntGauge = register_int_gauge!(
        "xiranet_sessions_active",
        "Currently active sessions on this node"
    ).unwrap();

    /// MFA event'leri — enroll_started, enroll_verified, login_success, login_failed,
    /// disabled_by_admin.
    pub static ref MFA_EVENTS: IntCounterVec = register_int_counter_vec!(
        "xiranet_mfa_events_total",
        "MFA lifecycle event counts",
        &["event"]
    ).unwrap();

    /// Boot-time veya runtime'da JWT init/validation hataları.
    pub static ref JWT_REJECTS: IntCounter = register_int_counter!(
        "xiranet_jwt_rejects_total",
        "JWT validation rejections (signature/exp/alg/iss/aud)"
    ).unwrap();
}

/// SSRF kategori isim normalize: UrlGuardError → kısa label.
pub fn ssrf_category(err: &str) -> &'static str {
    if err.contains("metadata") {
        "metadata"
    } else if err.contains("loopback") || err.contains("127.") || err.contains("::1") {
        "loopback"
    } else if err.contains("private") || err.contains("10.") || err.contains("192.168") {
        "private"
    } else if err.contains("scheme") {
        "bad_scheme"
    } else if err.contains("DNS") {
        "dns"
    } else {
        "other"
    }
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
