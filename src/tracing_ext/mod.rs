use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use tracing_appender::rolling;

/// Gelişmiş tracing konfigürasyonu: console + file + OpenTelemetry-ready
pub fn init_tracing(log_level: &str, file_enabled: bool, file_path: &str, rotation: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{},actix_web=info", log_level)));

    // Console layer
    let console_layer = fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .compact();

    if file_enabled {
        // File layer
        let dir = std::path::Path::new(file_path)
            .parent()
            .unwrap_or(std::path::Path::new("logs"));
        let filename = std::path::Path::new(file_path)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new("xiranet.log"))
            .to_str()
            .unwrap_or("xiranet.log");

        let _ = std::fs::create_dir_all(dir);

        let file_appender = match rotation {
            "hourly" => rolling::hourly(dir, filename),
            "never" => rolling::never(dir, filename),
            _ => rolling::daily(dir, filename),
        };

        let file_layer = fmt::layer()
            .with_writer(file_appender)
            .with_target(true)
            .with_thread_ids(true)
            .json();

        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .with(file_layer)
            .init();

        tracing::info!("Tracing initialized: console + file ({})", file_path);
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .init();

        tracing::info!("Tracing initialized: console only");
    }
}

/// OpenTelemetry-ready trace context propagation helper
pub fn extract_trace_id(headers: &actix_web::http::header::HeaderMap) -> Option<String> {
    headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            // W3C Trace Context format: 00-{trace_id}-{parent_id}-{trace_flags}
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() >= 2 {
                parts[1].to_string()
            } else {
                s.to_string()
            }
        })
}

/// Generate a new trace ID
pub fn generate_trace_id() -> String {
    uuid::Uuid::new_v4().to_string().replace("-", "")
}
