use actix_web::{web, HttpResponse};
use uuid::Uuid;
use std::sync::Arc;

use crate::registry::models::{
    ApiResponse, RegisterServiceRequest, ServiceListResponse, ServiceStatus, StatsResponse,
};
use crate::registry::ServiceRegistry;
use crate::gateway::cache::ResponseCache;
use crate::gateway::circuit_breaker::CircuitBreakerManager;
use crate::plugins::PluginManager;

/// GET /xira/services
pub async fn list_services(registry: web::Data<ServiceRegistry>) -> HttpResponse {
    let services = registry.list_all();
    let response = ApiResponse::ok(
        format!("{} service(s) registered", services.len()),
        ServiceListResponse { total: services.len(), services },
    );
    HttpResponse::Ok().json(response)
}

/// POST /xira/services
pub async fn register_service(
    registry: web::Data<ServiceRegistry>,
    body: web::Json<RegisterServiceRequest>,
) -> HttpResponse {
    let req = body.into_inner();
    if req.name.is_empty() || req.prefix.is_empty() || req.upstream.is_empty() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error("name, prefix, and upstream are required"));
    }

    let entry = registry.register_advanced(req);
    HttpResponse::Created().json(ApiResponse::ok(
        format!("Service '{}' registered successfully", entry.name), entry,
    ))
}

/// DELETE /xira/services/{id}
pub async fn unregister_service(
    registry: web::Data<ServiceRegistry>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = match Uuid::parse_str(&path.into_inner()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid UUID")),
    };

    match registry.unregister(&id) {
        Some(entry) => HttpResponse::Ok().json(ApiResponse::ok(format!("Service '{}' unregistered", entry.name), entry)),
        None => HttpResponse::NotFound().json(ApiResponse::<()>::error("Service not found")),
    }
}

/// GET /xira/services/{id}/health
pub async fn check_service_health(
    registry: web::Data<ServiceRegistry>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = match Uuid::parse_str(&path.into_inner()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Invalid UUID")),
    };

    let services = registry.list_all();
    let service = match services.iter().find(|s| s.id == id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Service not found")),
    };

    let health_url = format!("{}{}", service.upstream, service.health_endpoint);
    let client = reqwest::Client::new();

    match client.get(&health_url).timeout(std::time::Duration::from_secs(5)).send().await {
        Ok(resp) if resp.status().is_success() => {
            registry.update_status(&id, ServiceStatus::Up);
            HttpResponse::Ok().json(ApiResponse::ok(format!("'{}' is UP", service.name), serde_json::json!({"name": service.name, "status": "UP"})))
        }
        Ok(resp) => {
            registry.update_status(&id, ServiceStatus::Down);
            HttpResponse::Ok().json(ApiResponse::ok(format!("'{}' is DOWN ({})", service.name, resp.status()), serde_json::json!({"name": service.name, "status": "DOWN", "http_status": resp.status().as_u16()})))
        }
        Err(e) => {
            registry.update_status(&id, ServiceStatus::Down);
            HttpResponse::Ok().json(ApiResponse::ok(format!("'{}' is DOWN: {}", service.name, e), serde_json::json!({"name": service.name, "status": "DOWN", "error": e.to_string()})))
        }
    }
}

/// GET /xira/stats
pub async fn get_stats(
    registry: web::Data<ServiceRegistry>,
    start_time: web::Data<std::time::Instant>,
) -> HttpResponse {
    let db_stats = registry.storage().and_then(|s| s.get_stats().ok());

    let stats = StatsResponse {
        total_services: registry.count(),
        services_up: registry.count_by_status(&ServiceStatus::Up),
        services_down: registry.count_by_status(&ServiceStatus::Down),
        services_unknown: registry.count_by_status(&ServiceStatus::Unknown),
        total_requests: registry.total_requests(),
        uptime_seconds: start_time.elapsed().as_secs(),
        db_stats,
    };
    HttpResponse::Ok().json(ApiResponse::ok("xiraNET stats", stats))
}

/// GET /xira/health
pub async fn gateway_health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "UP",
        "service": "xiraNET",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

/// GET /xira/events
pub async fn get_events(registry: web::Data<ServiceRegistry>) -> HttpResponse {
    let events = registry.storage()
        .and_then(|s| s.get_recent_events(100).ok())
        .unwrap_or_default();

    HttpResponse::Ok().json(ApiResponse::ok(
        format!("{} recent events", events.len()),
        serde_json::json!({ "events": events }),
    ))
}

/// GET /xira/logs
pub async fn get_logs(registry: web::Data<ServiceRegistry>) -> HttpResponse {
    let logs = registry.storage()
        .and_then(|s| s.get_recent_logs(100).ok())
        .unwrap_or_default();

    HttpResponse::Ok().json(ApiResponse::ok(
        format!("{} recent logs", logs.len()),
        serde_json::json!({ "logs": logs }),
    ))
}

/// POST /xira/cache/clear
pub async fn clear_cache(cache: web::Data<Arc<ResponseCache>>) -> HttpResponse {
    cache.clear();
    HttpResponse::Ok().json(ApiResponse::ok("Cache cleared", serde_json::json!({"cleared": true})))
}

/// GET /xira/circuit-breakers
pub async fn get_circuit_breakers(cb: web::Data<CircuitBreakerManager>) -> HttpResponse {
    let report = cb.report();
    HttpResponse::Ok().json(ApiResponse::ok("Circuit breaker states", serde_json::json!({"breakers": report})))
}

/// GET /xira/plugins
pub async fn get_plugins(pm: web::Data<PluginManager>) -> HttpResponse {
    let plugins = pm.list_plugins();
    HttpResponse::Ok().json(ApiResponse::ok(format!("{} plugins loaded", plugins.len()), serde_json::json!({"plugins": plugins})))
}

/// GET /xira/log-stats
pub async fn get_log_stats() -> HttpResponse {
    let stats = crate::logging::log_stats("logs");
    HttpResponse::Ok().json(ApiResponse::ok("Log statistics", stats))
}
