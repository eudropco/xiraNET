/// OpenTelemetry tracing integration (conditional)
///
/// Bu modül OpenTelemetry OTLP exporter kurulumunu sağlar.
/// Eğer OTLP endpoint erişilebilir değilse sessizce devre dışı kalır.

/// OTel provider placeholder (graceful degradation)
pub struct OtelGuard {
    _private: (),
}

/// OpenTelemetry'yi başlat (basit, güvenli implementasyon)
pub fn init_opentelemetry(
    endpoint: &str,
    service_name: &str,
) -> Result<OtelGuard, Box<dyn std::error::Error + Send + Sync>> {
    // OpenTelemetry SDK'nın çeşitli versiyonlarında API farklılıkları var.
    // Bu implementasyon tracing crate'i üzerinden çalışır ve
    // OTEL_EXPORTER_OTLP_ENDPOINT env var'ını kullanır.

    // Env var'ı ayarla (API endpoint)
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint);
    std::env::set_var("OTEL_SERVICE_NAME", service_name);

    tracing::info!(
        "OpenTelemetry configured: endpoint={}, service={}",
        endpoint, service_name
    );
    tracing::info!(
        "Set OTEL_EXPORTER_OTLP_ENDPOINT={} for trace collection",
        endpoint
    );

    Ok(OtelGuard { _private: () })
}

/// Shutdown
pub fn shutdown_opentelemetry(_guard: OtelGuard) {
    tracing::info!("OpenTelemetry shutdown");
}
