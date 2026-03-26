use actix_web::{web, HttpResponse};
use crate::config::XiraConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Runtime config update request
#[derive(serde::Deserialize)]
pub struct ConfigUpdateRequest {
    /// Güncellenecek section
    pub section: String,
    /// Yeni değerler (JSON)
    pub values: serde_json::Value,
}

/// GET /xira/config — Mevcut config'i döndür
pub async fn get_config(
    shared_config: web::Data<Arc<RwLock<XiraConfig>>>,
) -> HttpResponse {
    let config = shared_config.read().await;

    HttpResponse::Ok().json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "gateway": {
            "host": config.gateway.host,
            "port": config.gateway.port,
            "workers": config.gateway.workers,
        },
        "rate_limit": {
            "max_requests": config.rate_limit.max_requests,
            "window_secs": config.rate_limit.window_secs,
        },
        "cache": {
            "enabled": config.cache.enabled,
            "max_entries": config.cache.max_entries,
            "ttl_secs": config.cache.ttl_secs,
        },
        "circuit_breaker": {
            "failure_threshold": config.circuit_breaker.failure_threshold,
            "reset_timeout_secs": config.circuit_breaker.reset_timeout_secs,
            "half_open_max_requests": config.circuit_breaker.half_open_max_requests,
        },
        "retry": {
            "max_retries": config.retry.max_retries,
            "delay_ms": config.retry.delay_ms,
            "backoff_multiplier": config.retry.backoff_multiplier,
        },
        "health": {
            "interval_secs": config.health.interval_secs,
            "timeout_secs": config.health.timeout_secs,
        },
        "jwt": {
            "enabled": config.jwt.enabled,
            "algorithm": config.jwt.algorithm,
        },
        "ip_filter": {
            "enabled": config.ip_filter.enabled,
            "whitelist_count": config.ip_filter.whitelist.len(),
            "blacklist_count": config.ip_filter.blacklist.len(),
        },
        "plugins": {
            "enabled": config.plugins.enabled,
            "directory": config.plugins.directory,
        },
        "alerting": {
            "enabled": config.alerting.enabled,
            "on_service_down": config.alerting.on_service_down,
            "on_service_up": config.alerting.on_service_up,
        },
        "logging": {
            "level": config.logging.level,
            "file_enabled": config.logging.file_enabled,
        },
    }))
}

/// PUT /xira/config — Runtime config güncelle
pub async fn update_config(
    shared_config: web::Data<Arc<RwLock<XiraConfig>>>,
    body: web::Json<ConfigUpdateRequest>,
) -> HttpResponse {
    let mut config = shared_config.write().await;

    match body.section.as_str() {
        "rate_limit" => {
            if let Some(max) = body.values.get("max_requests").and_then(|v| v.as_u64()) {
                config.rate_limit.max_requests = max as u32;
            }
            if let Some(window) = body.values.get("window_secs").and_then(|v| v.as_u64()) {
                config.rate_limit.window_secs = window;
            }
            tracing::info!("Runtime config updated: rate_limit → max={}, window={}s",
                config.rate_limit.max_requests, config.rate_limit.window_secs);
        }
        "cache" => {
            if let Some(enabled) = body.values.get("enabled").and_then(|v| v.as_bool()) {
                config.cache.enabled = enabled;
            }
            if let Some(ttl) = body.values.get("ttl_secs").and_then(|v| v.as_u64()) {
                config.cache.ttl_secs = ttl;
            }
            tracing::info!("Runtime config updated: cache → enabled={}, ttl={}s",
                config.cache.enabled, config.cache.ttl_secs);
        }
        "circuit_breaker" => {
            if let Some(threshold) = body.values.get("failure_threshold").and_then(|v| v.as_u64()) {
                config.circuit_breaker.failure_threshold = threshold as u32;
            }
            if let Some(timeout) = body.values.get("reset_timeout_secs").and_then(|v| v.as_u64()) {
                config.circuit_breaker.reset_timeout_secs = timeout;
            }
            tracing::info!("Runtime config updated: circuit_breaker → threshold={}, timeout={}s",
                config.circuit_breaker.failure_threshold, config.circuit_breaker.reset_timeout_secs);
        }
        "retry" => {
            if let Some(max) = body.values.get("max_retries").and_then(|v| v.as_u64()) {
                config.retry.max_retries = max as u32;
            }
            if let Some(delay) = body.values.get("delay_ms").and_then(|v| v.as_u64()) {
                config.retry.delay_ms = delay;
            }
            tracing::info!("Runtime config updated: retry → max={}, delay={}ms",
                config.retry.max_retries, config.retry.delay_ms);
        }
        "alerting" => {
            if let Some(enabled) = body.values.get("enabled").and_then(|v| v.as_bool()) {
                config.alerting.enabled = enabled;
            }
            tracing::info!("Runtime config updated: alerting → enabled={}", config.alerting.enabled);
        }
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Unknown config section",
                "section": body.section,
                "valid_sections": ["rate_limit", "cache", "circuit_breaker", "retry", "alerting"],
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "updated",
        "section": body.section,
        "message": format!("Config section '{}' updated successfully", body.section),
    }))
}
